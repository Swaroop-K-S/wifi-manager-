"""
Sentinel AI: Behavioral Traffic Fingerprinting + Real DPI App Telemetry Engine
Fuses verified DPI app detections (TLS/QUIC SNI) with packet-burst heuristics
to produce high-confidence, human-readable activity labels for each device.
"""
import time
from typing import Dict, Any, Optional

# DPI-verified app labels emitted when SNI/QUIC evidence is available
_DPI_LABEL_MAP = {
    # Streaming
    "YouTube":                 ("YouTube (QUIC/TLS Verified)",       "High-Def Streaming",          "📺"),
    "Netflix":                 ("Netflix (TLS Verified)",             "High-Def Streaming",          "📺"),
    "Spotify":                 ("Spotify (Active Stream)",            "Music Streaming",             "🎵"),
    "JioHotstar / Disney+":   ("JioHotstar / Disney+ (Verified)",   "High-Def Streaming",          "📺"),
    "Amazon Prime Video":      ("Prime Video (TLS Verified)",         "High-Def Streaming",          "📺"),
    "Twitch":                  ("Twitch Live (TLS Verified)",         "Live Stream Watching",        "📡"),
    "TikTok":                  ("TikTok Reels (DPI Verified)",        "Social Media Doomscrolling",  "📱"),
    # Social Media
    "Instagram":               ("Instagram Reels (DPI Verified)",     "Social Media Doomscrolling",  "📱"),
    "WhatsApp":                ("WhatsApp (Active)",                  "Live Voice / Video Call",     "📞"),
    "Facebook / Meta":         ("Facebook / Meta (DPI Verified)",     "Social Media Doomscrolling",  "📱"),
    "X (Twitter)":             ("X / Twitter (DPI Verified)",         "Social Media Doomscrolling",  "📱"),
    "Reddit":                  ("Reddit (DPI Verified)",              "Active Web Browsing",         "🌐"),
    "Snapchat":                ("Snapchat (DPI Verified)",            "Social Media Doomscrolling",  "📱"),
    "Telegram":                ("Telegram (Active)",                  "Live Voice / Video Call",     "📞"),
    # Gaming
    "Discord":                 ("Discord / Gaming (DPI Verified)",    "Online Multiplayer Gaming",   "🎮"),
    "Steam":                   ("Steam (DPI Verified)",               "Heavy File Transfer / Cloud", "☁️"),
    "Valorant / Riot Games":   ("Valorant / Riot (DPI Verified)",     "Online Multiplayer Gaming",   "🎮"),
    "BGMI / PUBG":             ("BGMI / PUBG (DPI Verified)",         "Online Multiplayer Gaming",   "🎮"),
    "Epic Games":              ("Epic Games (DPI Verified)",          "Online Multiplayer Gaming",   "🎮"),
    "Roblox":                  ("Roblox (DPI Verified)",              "Online Multiplayer Gaming",   "🎮"),
    # Dev & AI
    "ChatGPT":                 ("ChatGPT (TLS Verified)",             "Dev & AI",                   "🤖"),
    "Claude AI":               ("Claude AI (TLS Verified)",           "Dev & AI",                   "🤖"),
    "Google Gemini":           ("Google Gemini (TLS Verified)",       "Dev & AI",                   "🤖"),
    "GitHub":                  ("GitHub (TLS Verified)",              "Dev & AI",                   "💻"),
}

_IDLE_APPS    = {"", "Idle", "Web Browser", "Background System Sync"}
_DPI_TTL_SECS = 30.0   # seconds before a DPI label expires


class SentinelAI:
    """
    Two-layer activity inference:
      Layer 1 (DPI Priority): If a TLS/QUIC-verified app was seen within 30s,
                              emit a 99% confidence label (e.g. "YouTube (QUIC/TLS Verified)").
      Layer 2 (Behavioral):  Pure KB/s burst-pattern heuristics, used when DPI has no
                              recent observation or for apps not in the DPI map.
    """

    def __init__(self):
        # State tracking per device IP
        self.device_telemetry: Dict[str, Dict[str, Any]] = {}

    def analyze_device_traffic(
        self,
        ip: str,
        current_dl_kbps: float,
        current_ul_kbps: float,
        detected_app: Optional[str] = None,
        last_domain: Optional[str]  = None,
        active_sockets_count: int   = 1,
    ) -> Dict[str, Any]:
        """
        Returns a sentinel analysis dict:
            behavior_state      : human-readable activity (e.g. 'High-Def Streaming')
            predicted_app       : specific app label (e.g. 'YouTube (QUIC/TLS Verified)')
            confidence_percent  : 85-99
            icon                : emoji
            dpi_verified        : True if label comes from real SNI/QUIC evidence
            last_domain         : last inspected domain (for UI display)
        """
        now = time.time()
        if ip not in self.device_telemetry:
            self.device_telemetry[ip] = {
                "burst_samples":    [],
                "last_state":       "Passive Idle",
                "confidence":       95,
                "app_guess":        "Idle Background Sync",
                "icon":             "💤",
                "dpi_app":          "",
                "dpi_app_seen_at":  0.0,
            }

        rec         = self.device_telemetry[ip]
        total_kbps  = current_dl_kbps + current_ul_kbps

        rec["burst_samples"].append((now, total_kbps))
        rec["burst_samples"] = rec["burst_samples"][-15:]

        # ── Layer 1: DPI-Verified App Label (priority) ────────────────────────
        if detected_app and detected_app not in _IDLE_APPS:
            rec["dpi_app"]         = detected_app
            rec["dpi_app_seen_at"] = now

        dpi_app    = rec.get("dpi_app", "")
        dpi_age    = now - rec.get("dpi_app_seen_at", 0.0)
        dpi_fresh  = bool(dpi_app) and (dpi_age < _DPI_TTL_SECS)

        if dpi_fresh and dpi_app in _DPI_LABEL_MAP:
            app_label, behav_state, icon = _DPI_LABEL_MAP[dpi_app]
            # Still run behavioral pass to get the correct state classification
            behav_state = self._behavioral_state(current_dl_kbps, current_ul_kbps, active_sockets_count)
            return {
                "behavior_state":     behav_state,
                "predicted_app":      app_label,
                "confidence_percent": 99,
                "icon":               icon,
                "dpi_verified":       True,
                "last_domain":        last_domain or "",
            }

        # ── Layer 2: Behavioral Heuristics Fallback ───────────────────────────
        behav_state, app_guess, icon, confidence = self._behavioral_classify(
            current_dl_kbps, current_ul_kbps, active_sockets_count
        )

        rec["last_state"] = behav_state
        rec["confidence"] = confidence
        rec["app_guess"]  = app_guess
        rec["icon"]       = icon

        return {
            "behavior_state":     behav_state,
            "predicted_app":      app_guess,
            "confidence_percent": confidence,
            "icon":               icon,
            "dpi_verified":       False,
            "last_domain":        last_domain or "",
        }

    # ── Behavioral Helpers ────────────────────────────────────────────────────

    def _behavioral_state(
        self,
        dl: float,
        ul: float,
        sockets: int,
    ) -> str:
        """Returns a plain behavioral state string from traffic numbers."""
        total = dl + ul
        if total < 80:
            return "Idle / Passive"
        if dl > 6000:
            return "High-Def Streaming"
        if 800 <= dl <= 5500 and ul < 600:
            return "Social Media Doomscrolling"
        if dl > 200 and ul > 150 and (dl / max(1, ul)) < 3.5:
            return "Live Voice / Video Call" if sockets >= 3 else "Online Multiplayer Gaming"
        if dl > 2500 and ul > 800:
            return "Heavy File Transfer / Cloud"
        return "Active Web Browsing"

    def _behavioral_classify(
        self,
        dl: float,
        ul: float,
        sockets: int,
    ):
        """Returns (state, app_guess, icon, confidence) from raw throughput."""
        total = dl + ul
        if total < 80:
            return ("Idle / Passive",
                    "Background System Sync",            "💤", 98)
        if dl > 6000:
            return ("High-Def Streaming",
                    "4K/1080p Video Buffer (YouTube / Netflix)", "📺", 94)
        if 800 <= dl <= 5500 and ul < 600:
            return ("Social Media Doomscrolling",
                    "Video Shorts / Reels (Instagram / TikTok)", "📱", 91)
        if dl > 200 and ul > 150 and (dl / max(1, ul)) < 3.5:
            if sockets >= 3:
                return ("Live Voice / Video Call",
                        "WhatsApp / Discord / Zoom Call",        "📞", 89)
            return ("Online Multiplayer Gaming",
                    "Real-time Game Server (Low-Latency UDP)",   "🎮", 92)
        if dl > 2500 and ul > 800:
            return ("Heavy File Transfer / Cloud",
                    "Cloud Sync / Steam Patch / Large Download", "☁️", 88)
        return ("Active Web Browsing",
                "Standard Web Browsing / Articles",              "🌐", 85)


sentinel_ai = SentinelAI()
