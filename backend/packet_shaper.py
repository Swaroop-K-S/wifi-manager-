"""
Windows Kernel Packet Shaper (WinDivert / pydivert)
Enforces Block, Pause, Bandwidth Cap, and Lag Switch at the OS network-stack level.
Requires pydivert>=2.1.0 and Npcap / WinDivert driver installed.
Falls back gracefully if pydivert is unavailable or process lacks Admin rights.
"""
import time
import threading
import socket
import logging
from typing import Dict, Any, Optional

log = logging.getLogger("PacketShaper")

# ── Graceful pydivert import ─────────────────────────────────────────────────
try:
    import pydivert
    _PYDIVERT_OK = True
except ImportError:
    pydivert = None  # type: ignore
    _PYDIVERT_OK = False
    log.warning("[PacketShaper] pydivert not installed — kernel enforcement disabled. "
                "Run: pip install pydivert")


def _get_local_ip() -> str:
    """Returns this machine's primary LAN IP without sending any packets."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _get_gateway_ip() -> str:
    """Best-effort default gateway extraction (Windows only)."""
    try:
        import subprocess
        out = subprocess.check_output("ipconfig", text=True, timeout=5)
        for line in out.splitlines():
            if "Default Gateway" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    gw = parts[-1].strip()
                    if gw and gw != "":
                        return gw
    except Exception:
        pass
    return "192.168.1.1"


# ── Token Bucket State ────────────────────────────────────────────────────────
class _TokenBucket:
    """Per-IP token bucket for bandwidth throttling."""
    __slots__ = ("tokens", "rate_bytes_per_sec", "last_refill")

    def __init__(self, rate_kbps: float):
        self.rate_bytes_per_sec = rate_kbps * 1024.0
        self.tokens = self.rate_bytes_per_sec          # Start full
        self.last_refill = time.monotonic()

    def update_rate(self, rate_kbps: float):
        self.rate_bytes_per_sec = rate_kbps * 1024.0

    def allowed(self, packet_bytes: int) -> bool:
        """Returns True if the packet fits within the current token budget."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.last_refill = now
        self.tokens = min(
            self.rate_bytes_per_sec,                   # cap at 1-sec burst
            self.tokens + elapsed * self.rate_bytes_per_sec,
        )
        if self.tokens >= packet_bytes:
            self.tokens -= packet_bytes
            return True
        return False                                   # Drop — over limit


# ── Policy Cache entry ────────────────────────────────────────────────────────
#   { "ip": { "blocked": bool, "limit_kbps": int, "lag_ms": int } }

class KernelPacketShaper:
    """
    Singleton that:
      1. Polls SQLite every second for per-device policies (block / throttle / lag).
      2. Opens a WinDivert handle to intercept all non-loopback IP packets.
      3. Enforces those policies at the Windows network stack level.
    """

    # WinDivert filter — captures all IP except loopback
    _FILTER = (
        "ip and "
        "ip.SrcAddr != 127.0.0.1 and "
        "ip.DstAddr != 127.0.0.1"
    )

    def __init__(self):
        self._policy_lock = threading.Lock()
        self._policies: Dict[str, Dict[str, Any]] = {}   # ip -> policy
        self._buckets: Dict[str, _TokenBucket] = {}      # ip -> TokenBucket

        self._running = False
        self._divert_thread: Optional[threading.Thread] = None
        self._sync_thread: Optional[threading.Thread] = None
        self._force_sync_event = threading.Event()

        self.local_ip = _get_local_ip()
        self.gateway_ip = _get_gateway_ip()

        self.enabled = _PYDIVERT_OK
        if not self.enabled:
            log.warning("[PacketShaper] Kernel enforcement disabled (no pydivert).")

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self):
        """Start policy-sync and (if pydivert available) divert threads."""
        if self._running:
            return
        self._running = True

        # Policy sync thread — runs regardless of pydivert availability
        self._sync_thread = threading.Thread(
            target=self._sync_policies_loop, daemon=True, name="PktShaper-Sync"
        )
        self._sync_thread.start()

        # Kernel divert thread — only if pydivert is present
        if self.enabled:
            self._divert_thread = threading.Thread(
                target=self._divert_loop, daemon=True, name="PktShaper-Divert"
            )
            self._divert_thread.start()
            log.info("[PacketShaper] WinDivert kernel loop started.")
        else:
            log.info("[PacketShaper] Running in policy-cache-only mode (no WinDivert).")

    def stop(self):
        self._running = False

    def force_sync(self):
        """Called by main.py immediately after any admin action to flush stale policy cache."""
        self._force_sync_event.set()

    # ── Policy Sync Loop ──────────────────────────────────────────────────────

    def _sync_policies_loop(self):
        while self._running:
            self._do_sync()
            # Wait up to 1.0 s OR until force_sync() is called
            self._force_sync_event.wait(timeout=1.0)
            self._force_sync_event.clear()

    def _do_sync(self):
        """Read all device rows and rebuild the policy dictionary."""
        try:
            from backend.database import get_db
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ip, is_blocked, is_paused, bandwidth_limit_kbps, artificial_latency_ms "
                "FROM devices"
            )
            rows = cursor.fetchall()
            conn.close()

            new_policies: Dict[str, Dict[str, Any]] = {}
            for row in rows:
                ip = row["ip"]
                if not ip:
                    continue
                blocked = bool(row["is_blocked"] or row["is_paused"])
                limit_kbps = int(row["bandwidth_limit_kbps"] or 0)
                lag_ms = int(row["artificial_latency_ms"] or 0)
                new_policies[ip] = {
                    "blocked":    blocked,
                    "limit_kbps": limit_kbps,
                    "lag_ms":     lag_ms,
                }

            with self._policy_lock:
                self._policies = new_policies
                # Reconcile bucket rates with new policy
                for ip, pol in new_policies.items():
                    lk = pol["limit_kbps"]
                    if lk > 0:
                        if ip in self._buckets:
                            self._buckets[ip].update_rate(lk)
                        else:
                            self._buckets[ip] = _TokenBucket(lk)
                    else:
                        self._buckets.pop(ip, None)

        except Exception as e:
            log.debug("[PacketShaper] Policy sync error: %s", e)

    # ── Throttle Helper ───────────────────────────────────────────────────────

    def _throttle_allowed(self, ip: str, packet_len: int) -> bool:
        """Returns True if packet passes the token-bucket rate limit."""
        bucket = self._buckets.get(ip)
        if bucket is None:
            return True
        return bucket.allowed(packet_len)

    # ── WinDivert Kernel Loop ─────────────────────────────────────────────────

    def _divert_loop(self):
        """
        Main WinDivert intercept loop.
        Opens a kernel-level handle, inspects each packet, and either:
          - forwards it unchanged,
          - drops it (block / throttle over-limit),
          - or delays it (lag injection via Timer).
        """
        try:
            with pydivert.WinDivert(self._FILTER) as w:
                log.info("[PacketShaper] WinDivert handle opened successfully.")
                while self._running:
                    try:
                        packet = w.recv()
                    except Exception as e:
                        if self._running:
                            log.debug("[PacketShaper] recv error: %s", e)
                        continue

                    src = packet.src_addr
                    dst = packet.dst_addr

                    # ── Determine which end is the client device ───────────
                    # Ignore our own machine and the gateway so admin is never locked out
                    if src in (self.local_ip, self.gateway_ip) and dst in (self.local_ip, self.gateway_ip):
                        w.send(packet)
                        continue

                    # Figure out the "other" (remote client) IP
                    if src == self.local_ip or src == self.gateway_ip:
                        client_ip = dst
                    else:
                        client_ip = src

                    # Never apply policy to our own machine or gateway
                    if client_ip in (self.local_ip, self.gateway_ip):
                        w.send(packet)
                        continue

                    with self._policy_lock:
                        pol = self._policies.get(client_ip)

                    if pol is None:
                        # No policy entry -> allow (unknown device)
                        w.send(packet)
                        continue

                    # ── Block / Pause Enforcement ──────────────────────────
                    if pol["blocked"]:
                        # Always allow DNS (UDP 53) so our sinkhole can respond
                        # Always allow TCP 80  so the port-80 redirector returns a 302
                        # Always allow TCP 8000 so the captive portal page loads
                        src_port = getattr(packet, "src_port", None)
                        dst_port = getattr(packet, "dst_port", None)
                        is_udp   = packet.udp is not None if hasattr(packet, "udp") else False
                        is_tcp   = packet.tcp is not None if hasattr(packet, "tcp") else False

                        dns_pass  = is_udp and (src_port == 53 or dst_port == 53)
                        http_pass = is_tcp and (src_port == 80  or dst_port == 80)
                        cap_pass  = is_tcp and (src_port == 8000 or dst_port == 8000)

                        if dns_pass or http_pass or cap_pass:
                            w.send(packet)
                        # else: drop silently (no send)
                        continue

                    # ── Bandwidth Cap Enforcement ──────────────────────────
                    if pol["limit_kbps"] > 0:
                        if not self._throttle_allowed(client_ip, len(packet.raw)):
                            continue  # Drop — over rate limit

                    # ── Lag Switch Enforcement ─────────────────────────────
                    lag = pol["lag_ms"]
                    if lag > 0:
                        # Non-blocking: schedule send via Timer
                        def _delayed_send(pkt=packet):
                            try:
                                w.send(pkt)
                            except Exception:
                                pass
                        t = threading.Timer(lag / 1000.0, _delayed_send)
                        t.daemon = True
                        t.start()
                        continue

                    # ── No restriction — forward ───────────────────────────
                    w.send(packet)

        except PermissionError:
            log.error(
                "[PacketShaper] WinDivert requires Administrator privileges. "
                "Please run the server as Admin to enable kernel enforcement."
            )
            self.enabled = False
        except OSError as e:
            log.error(
                "[PacketShaper] WinDivert driver not found or failed to open: %s. "
                "Install WinDivert from https://reqrypt.org/windivert.html", e
            )
            self.enabled = False
        except Exception as e:
            log.error("[PacketShaper] Unexpected divert loop error: %s", e)
            self.enabled = False


# ── Module-level singleton ────────────────────────────────────────────────────
packet_shaper = KernelPacketShaper()
