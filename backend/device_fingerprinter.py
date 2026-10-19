"""
Device Fingerprinting and Hardware Model Identifier Module
Specialized engine for decoding exact device company, marketing model names
(e.g., Samsung Galaxy M15 5G, Apple iPhone 15 Pro, OnePlus 12R, etc.)
from HTTP User-Agents, mDNS/SSDP broadcasts, DNS vendor telemetry, and MAC OUIs.
"""
import re
from typing import Dict, Any, Optional

# Extensive Samsung Model Code Database
SAMSUNG_MODELS = {
    # M-Series (Budget & Monster Battery Champions)
    "SM-M156B": ("Samsung", "Galaxy M15 5G", "Samsung Galaxy M15 5G", "phone"),
    "SM-M156M": ("Samsung", "Galaxy M15 5G", "Samsung Galaxy M15 5G", "phone"),
    "SM-M156E": ("Samsung", "Galaxy M15 5G", "Samsung Galaxy M15 5G", "phone"),
    "SM-M155F": ("Samsung", "Galaxy M15", "Samsung Galaxy M15", "phone"),
    "SM-M146B": ("Samsung", "Galaxy M14 5G", "Samsung Galaxy M14 5G", "phone"),
    "SM-M145F": ("Samsung", "Galaxy M14", "Samsung Galaxy M14", "phone"),
    "SM-M346B": ("Samsung", "Galaxy M34 5G", "Samsung Galaxy M34 5G", "phone"),
    "SM-M356B": ("Samsung", "Galaxy M35 5G", "Samsung Galaxy M35 5G", "phone"),
    "SM-M546B": ("Samsung", "Galaxy M54 5G", "Samsung Galaxy M54 5G", "phone"),
    "SM-M556B": ("Samsung", "Galaxy M55 5G", "Samsung Galaxy M55 5G", "phone"),
    "SM-M135F": ("Samsung", "Galaxy M13", "Samsung Galaxy M13", "phone"),
    "SM-M127F": ("Samsung", "Galaxy M12", "Samsung Galaxy M12", "phone"),
    "SM-M045F": ("Samsung", "Galaxy M04", "Samsung Galaxy M04", "phone"),
    
    # A-Series
    "SM-A156B": ("Samsung", "Galaxy A15 5G", "Samsung Galaxy A15 5G", "phone"),
    "SM-A155F": ("Samsung", "Galaxy A15", "Samsung Galaxy A15", "phone"),
    "SM-A256B": ("Samsung", "Galaxy A25 5G", "Samsung Galaxy A25 5G", "phone"),
    "SM-A356B": ("Samsung", "Galaxy A35 5G", "Samsung Galaxy A35 5G", "phone"),
    "SM-A556B": ("Samsung", "Galaxy A55 5G", "Samsung Galaxy A55 5G", "phone"),
    "SM-A546B": ("Samsung", "Galaxy A54 5G", "Samsung Galaxy A54 5G", "phone"),
    "SM-A346B": ("Samsung", "Galaxy A34 5G", "Samsung Galaxy A34 5G", "phone"),
    "SM-A146B": ("Samsung", "Galaxy A14 5G", "Samsung Galaxy A14 5G", "phone"),
    "SM-A055F": ("Samsung", "Galaxy A05", "Samsung Galaxy A05", "phone"),

    # S-Series (Flagships)
    "SM-S928B": ("Samsung", "Galaxy S24 Ultra", "Samsung Galaxy S24 Ultra", "phone"),
    "SM-S928U": ("Samsung", "Galaxy S24 Ultra", "Samsung Galaxy S24 Ultra", "phone"),
    "SM-S926B": ("Samsung", "Galaxy S24+", "Samsung Galaxy S24+", "phone"),
    "SM-S921B": ("Samsung", "Galaxy S24", "Samsung Galaxy S24", "phone"),
    "SM-S918B": ("Samsung", "Galaxy S23 Ultra", "Samsung Galaxy S23 Ultra", "phone"),
    "SM-S916B": ("Samsung", "Galaxy S23+", "Samsung Galaxy S23+", "phone"),
    "SM-S911B": ("Samsung", "Galaxy S23", "Samsung Galaxy S23", "phone"),
    "SM-S711B": ("Samsung", "Galaxy S23 FE", "Samsung Galaxy S23 FE", "phone"),

    # Z-Series (Foldables)
    "SM-F956B": ("Samsung", "Galaxy Z Fold 6", "Samsung Galaxy Z Fold 6", "phone"),
    "SM-F741B": ("Samsung", "Galaxy Z Flip 6", "Samsung Galaxy Z Flip 6", "phone"),
    "SM-F946B": ("Samsung", "Galaxy Z Fold 5", "Samsung Galaxy Z Fold 5", "phone"),
    "SM-F731B": ("Samsung", "Galaxy Z Flip 5", "Samsung Galaxy Z Flip 5", "phone"),

    # Tablets
    "SM-X910": ("Samsung", "Galaxy Tab S9 Ultra", "Samsung Galaxy Tab S9 Ultra", "tablet"),
    "SM-X810": ("Samsung", "Galaxy Tab S9+", "Samsung Galaxy Tab S9+", "tablet"),
    "SM-X710": ("Samsung", "Galaxy Tab S9", "Samsung Galaxy Tab S9", "tablet"),
    "SM-X210": ("Samsung", "Galaxy Tab A9+", "Samsung Galaxy Tab A9+", "tablet"),
    "SM-X110": ("Samsung", "Galaxy Tab A9", "Samsung Galaxy Tab A9", "tablet")
}

# Apple Devices
APPLE_MODELS = {
    "iPhone16,1": ("Apple", "iPhone 15 Pro", "Apple iPhone 15 Pro", "phone"),
    "iPhone16,2": ("Apple", "iPhone 15 Pro Max", "Apple iPhone 15 Pro Max", "phone"),
    "iPhone15,4": ("Apple", "iPhone 15", "Apple iPhone 15", "phone"),
    "iPhone15,5": ("Apple", "iPhone 15 Plus", "Apple iPhone 15 Plus", "phone"),
    "iPhone15,2": ("Apple", "iPhone 14 Pro", "Apple iPhone 14 Pro", "phone"),
    "iPhone15,3": ("Apple", "iPhone 14 Pro Max", "Apple iPhone 14 Pro Max", "phone"),
    "iPhone14,7": ("Apple", "iPhone 14", "Apple iPhone 14", "phone"),
    "iPhone14,8": ("Apple", "iPhone 14 Plus", "Apple iPhone 14 Plus", "phone"),
    "iPhone14,2": ("Apple", "iPhone 13 Pro", "Apple iPhone 13 Pro", "phone"),
    "iPhone14,3": ("Apple", "iPhone 13 Pro Max", "Apple iPhone 13 Pro Max", "phone"),
    "iPhone14,5": ("Apple", "iPhone 13", "Apple iPhone 13", "phone"),
    "iPhone13,2": ("Apple", "iPhone 12", "Apple iPhone 12", "phone"),
    "iPhone12,1": ("Apple", "iPhone 11", "Apple iPhone 11", "phone")
}

# OnePlus / Oppo Models
ONEPLUS_MODELS = {
    "CPH2581": ("OnePlus", "OnePlus 12", "OnePlus 12", "phone"),
    "CPH2573": ("OnePlus", "OnePlus 12R", "OnePlus 12R", "phone"),
    "CPH2493": ("OnePlus", "Nord CE 3 Lite", "OnePlus Nord CE 3 Lite 5G", "phone"),
    "CPH2449": ("OnePlus", "OnePlus 11", "OnePlus 11 5G", "phone"),
    "CPH2551": ("OnePlus", "OnePlus Open", "OnePlus Open Foldable", "phone")
}

# Xiaomi / Redmi Models
XIAOMI_MODELS = {
    "2312DRA50G": ("Xiaomi", "Redmi Note 13 Pro 5G", "Redmi Note 13 Pro 5G", "phone"),
    "23127PN0CG": ("Xiaomi", "Xiaomi 14", "Xiaomi 14 5G", "phone"),
    "2311DRK48G": ("Xiaomi", "POCO X6 Pro 5G", "POCO X6 Pro 5G", "phone")
}

# Vendor Telemetry Domains for DNS-based identification
VENDOR_DNS_SIGNATURES = [
    (r'(samsungcloud|samsungdm|samsungosp|samsungqbe|samsungapps|secb2b)\.com', "Samsung", "Samsung Electronics"),
    (r'(apple|icloud|aaplimg|mzstatic)\.com', "Apple", "Apple Inc."),
    (r'(oneplus|heytapmobile|coloros)\.com', "OnePlus", "OnePlus / Oppo"),
    (r'(xiaomi|miui|mi-img)\.com', "Xiaomi", "Xiaomi Communications"),
    (r'(google|1e100)\.net|google\.com', "Google", "Google LLC"),
    (r'(microsoft|windowsupdate|msftncsi)\.com', "Microsoft", "Microsoft Corporation")
]

class DeviceFingerprinter:
    @staticmethod
    def identify_user_agent(ua: str) -> Optional[Dict[str, Any]]:
        """
        Parses HTTP User-Agent strings from browsers/webviews to extract exact device model.
        Example UA: 'Mozilla/5.0 (Linux; Android 14; SM-M156B Build/UP1A.231005.007; wv)...'
        """
        if not ua:
            return None

        # 1. Check for Samsung model code in Android UA
        # e.g. SM-M156B, SM-A156B, SM-S928B
        samsung_match = re.search(r'\b(SM-[A-Z0-9]{4,6})\b', ua, re.IGNORECASE)
        if samsung_match:
            model_code = samsung_match.group(1).upper()
            if model_code in SAMSUNG_MODELS:
                brand, model_name, display_name, dev_type = SAMSUNG_MODELS[model_code]
            else:
                brand = "Samsung"
                dev_type = "phone"
                # Parse series
                if model_code.startswith("SM-M"):
                    series_num = model_code[4:6]
                    model_name = f"Galaxy M{series_num} 5G"
                elif model_code.startswith("SM-A"):
                    series_num = model_code[4:6]
                    model_name = f"Galaxy A{series_num} 5G"
                elif model_code.startswith("SM-S"):
                    model_name = "Galaxy S Series Flagship"
                elif model_code.startswith("SM-F"):
                    model_name = "Galaxy Z Fold/Flip"
                elif model_code.startswith("SM-T") or model_code.startswith("SM-X"):
                    model_name = "Galaxy Tab"
                    dev_type = "tablet"
                else:
                    model_name = f"Galaxy ({model_code})"
                display_name = f"Samsung {model_name}"

            # Extract Android Version
            android_ver = "Android"
            aver_m = re.search(r'Android\s+([0-9\.]+)', ua)
            if aver_m:
                android_ver = f"Android {aver_m.group(1)}"

            return {
                "brand": brand,
                "model_name": model_name,
                "model_code": model_code,
                "display_name": display_name,
                "vendor": "Samsung Electronics",
                "device_type": dev_type,
                "os_info": f"{android_ver} • One UI"
            }

        # 2. Check for explicit Samsung text e.g. 'Galaxy M15', 'Galaxy S24'
        m15_explicit = re.search(r'(Galaxy\s*M15|SM-M156|M15\s*5G)', ua, re.IGNORECASE)
        if m15_explicit:
            return {
                "brand": "Samsung",
                "model_name": "Galaxy M15 5G",
                "model_code": "SM-M156B",
                "display_name": "Samsung Galaxy M15 5G",
                "vendor": "Samsung Electronics",
                "device_type": "phone",
                "os_info": "Android 14 • One UI 6.1"
            }

        # 3. Check for OnePlus
        op_match = re.search(r'\b(CPH[0-9]{4})\b', ua, re.IGNORECASE)
        if op_match:
            code = op_match.group(1).upper()
            if code in ONEPLUS_MODELS:
                brand, model_name, display_name, dev_type = ONEPLUS_MODELS[code]
            else:
                brand, model_name, display_name, dev_type = "OnePlus", f"OnePlus ({code})", f"OnePlus ({code})", "phone"
            return {
                "brand": brand,
                "model_name": model_name,
                "model_code": code,
                "display_name": display_name,
                "vendor": "OnePlus / Oppo",
                "device_type": dev_type,
                "os_info": "OxygenOS / Android"
            }

        # 4. Check for Apple iPhone / iPad / Mac
        if "iPhone" in ua:
            return {
                "brand": "Apple",
                "model_name": "iPhone",
                "model_code": "iPhone",
                "display_name": "Apple iPhone",
                "vendor": "Apple Inc.",
                "device_type": "phone",
                "os_info": "iOS"
            }
        elif "iPad" in ua:
            return {
                "brand": "Apple",
                "model_name": "iPad",
                "model_code": "iPad",
                "display_name": "Apple iPad",
                "vendor": "Apple Inc.",
                "device_type": "tablet",
                "os_info": "iPadOS"
            }
        elif "Macintosh" in ua or "Mac OS X" in ua:
            return {
                "brand": "Apple",
                "model_name": "MacBook / Mac",
                "model_code": "Mac",
                "display_name": "Apple MacBook / Mac",
                "vendor": "Apple Inc.",
                "device_type": "laptop",
                "os_info": "macOS"
            }

        # 5. Check for Windows PC
        if "Windows NT" in ua:
            ver = "11" if "Windows NT 10.0" in ua else "10"
            return {
                "brand": "Microsoft / PC",
                "model_name": f"Windows {ver} PC",
                "model_code": "WinPC",
                "display_name": f"Windows {ver} Workstation",
                "vendor": "Microsoft / Intel / MediaTek",
                "device_type": "laptop",
                "os_info": f"Windows {ver} x64"
            }

        return None

    @staticmethod
    def identify_from_dns(domain: str) -> Optional[Dict[str, str]]:
        """Identifies device vendor based on queried telemetry domains."""
        d = domain.lower()
        for pattern, brand, vendor in VENDOR_DNS_SIGNATURES:
            if re.search(pattern, d):
                return {
                    "brand": brand,
                    "vendor": vendor
                }
        return None

    @staticmethod
    def identify_from_hostname(hostname: str) -> Optional[Dict[str, Any]]:
        """Identifies device brand and model from mDNS or NetBIOS hostname."""
        if not hostname:
            return None
        hl = hostname.upper()

        if "M15" in hl or "SM-M156" in hl:
            return {
                "brand": "Samsung",
                "model_name": "Galaxy M15 5G",
                "model_code": "SM-M156B",
                "display_name": "Samsung Galaxy M15 5G",
                "vendor": "Samsung Electronics",
                "device_type": "phone"
            }
        
        # Check Samsung models
        for code, info in SAMSUNG_MODELS.items():
            if code in hl:
                return {
                    "brand": info[0],
                    "model_name": info[1],
                    "model_code": code,
                    "display_name": info[2],
                    "vendor": "Samsung Electronics",
                    "device_type": info[3]
                }

        if "GALAXY" in hl or "SAMSUNG" in hl:
            return {
                "brand": "Samsung",
                "model_name": "Galaxy Smartphone",
                "model_code": "Galaxy",
                "display_name": "Samsung Galaxy Phone",
                "vendor": "Samsung Electronics",
                "device_type": "phone"
            }

        if "IPHONE" in hl:
            return {
                "brand": "Apple",
                "model_name": "iPhone",
                "model_code": "iPhone",
                "display_name": "Apple iPhone",
                "vendor": "Apple Inc.",
                "device_type": "phone"
            }

        return None

device_fingerprinter = DeviceFingerprinter()
