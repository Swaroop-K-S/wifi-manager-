"""
Real Live UDP DNS Server and Sinkhole (RFC 1035)
Listens on 0.0.0.0:53. Captures real domain queries from any client device,
enforces God-Mode domain blacklists, and forwards allowed queries to upstream DNS.
"""
import socket
import struct
import threading
import time
from typing import Callable, Optional

UPSTREAM_DNS = ("8.8.8.8", 53)

def parse_dns_domain(data: bytes, offset: int = 12) -> tuple:
    """Parses domain name from a raw DNS packet starting at offset."""
    labels = []
    curr = offset
    try:
        while curr < len(data):
            length = data[curr]
            if length == 0:
                curr += 1
                break
            if length >= 192: # DNS pointer compression
                curr += 2
                break
            curr += 1
            labels.append(data[curr:curr+length].decode("utf-8", errors="ignore"))
            curr += length
        domain = ".".join(labels).lower()
        return domain, curr
    except Exception:
        return "", curr

def build_blocked_response(query_data: bytes, query_domain: str) -> bytes:
    """Builds a DNS response pointing to 0.0.0.0 for blocked targets (Sinkhole)."""
    if len(query_data) < 12:
        return query_data
    # Transaction ID (2 bytes)
    tx_id = query_data[:2]
    # Standard query response, No error, Authoritative
    flags = b"\x81\x80"
    # QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"
    
    # Extract question section
    _, q_end = parse_dns_domain(query_data, 12)
    question = query_data[12:q_end + 4] # domain + QTYPE + QCLASS
    
    # Answer record: Name pointer to question (0xc00c), Type A (0x0001), Class IN (0x0001), TTL=60s, Len=4, IP=0.0.0.0
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x00\x00\x00\x00"
    return tx_id + flags + counts + question + answer

class LiveDNSServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 53):
        self.host = host
        self.port = port
        self.running = False
        self.sock = None
        self.thread = None
        self.query_callback: Optional[Callable] = None
        self.blacklist_checker: Optional[Callable] = None

    def start(self, query_callback: Callable = None, blacklist_checker: Callable = None):
        """Starts the live UDP DNS listener."""
        self.query_callback = query_callback
        self.blacklist_checker = blacklist_checker
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(1.0)
            self.running = True
            self.thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.thread.start()
            print(f"[DNS SERVER] Live DNS Sniffer running on {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[DNS SERVER] Could not bind to port {self.port}: {e}")
            return False

    def _listen_loop(self):
        while self.running:
            try:
                data, client_addr = self.sock.recvfrom(4096)
                if len(data) < 12:
                    continue
                threading.Thread(target=self._handle_query, args=(data, client_addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print("[DNS SERVER] Recv error:", e)

    def _handle_query(self, data: bytes, client_addr: tuple):
        client_ip = client_addr[0]
        domain, _ = parse_dns_domain(data, 12)
        if not domain:
            return

        is_blocked = False
        if self.blacklist_checker:
            is_blocked = self.blacklist_checker(domain)

        # Notify callback of real live query
        if self.query_callback:
            try:
                self.query_callback(client_ip=client_ip, domain=domain, is_blocked=is_blocked, payload_len=len(data))
            except Exception as e:
                print("[DNS SERVER] Callback error:", e)

        if is_blocked:
            # Drop or return sinkhole 0.0.0.0
            resp = build_blocked_response(data, domain)
            try:
                self.sock.sendto(resp, client_addr)
            except Exception:
                pass
        else:
            # Forward upstream to 8.8.8.8 and return real answer
            try:
                up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                up_sock.settimeout(2.0)
                up_sock.sendto(data, UPSTREAM_DNS)
                up_data, _ = up_sock.recvfrom(4096)
                up_sock.close()
                self.sock.sendto(up_data, client_addr)
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
