# AETHER SHIELD // NETGOD
### ⚡ Wi-Fi Router God-Mode Command Center & Deep Telemetry Hub
**Web Dashboard & Android Mobile Application**

AetherShield gives network administrators absolute visibility and control over their Wi-Fi router and every connected device.

---

## 🌟 Core Features

### 1. 📡 Real-Time Connected Device Activity
- **Subnet ARP & Ping Sweeper**: Actively scans the local subnet (`192.168.1.0/24`) to identify all connected hardware.
- **Hardware Identification**: Resolves MAC addresses to IEEE OUI manufacturers (Apple, Samsung, Intel, TP-Link, Sony PlayStation, Google, Xiaomi, IoT Smart Plugs).
- **Device Telemetry**: Real-time signal strength (dBm), ping latency (ms), hostnames, and IP assignments.

### 2. 📊 Total & Per-Device Data Usage
- **Live Bandwidth Speedometers**: Inbound Download (Mbps) and Outbound Upload (Mbps) throughput measured every second.
- **Data Volume Accounting**: Tracks cumulative data downloaded and uploaded (in GB) for the whole network and each individual phone, PC, and TV.
- **Real-Time Throughput Graph**: Dual-axis Chart.js visualization showing bandwidth spikes and traffic trends.
- **Category Breakdown**: Interactive doughnut chart breaking down traffic into Video Streaming, Social Media, Gaming, Dev & AI, Cloud Storage, and Threats.

### 3. 🕵️ "What They Are Doing on Wi-Fi" (Deep Activity & Domain Inspector)
- **Live Packet & DNS Stream**: Real-time log of every domain, website, and endpoint queried by every connected device:
  - YouTube (4K streams)
  - Instagram Reels & TikTok
  - Netflix & Prime Video
  - ChatGPT & AI APIs
  - Discord voice & Steam downloads
  - WhatsApp & Messaging sockets
- **Content Categorization**: Instant color-coded classification (Streaming, Social Media, Gaming, Dev, Threats).
- **Payload Accounting**: Shows exact bytes transferred per session/request.
- **Search & Filter**: Search by domain or filter down to a single suspicious device.

### 4. ⚡ Admin "God Mode" Controls
- **Kick / Block Device**: Instantly isolate any client from accessing the internet.
- **Pause Internet**: One-click freeze of internet access per device (great for dinner time or parental control).
- **Bandwidth Throttling**: Limit abusive bandwidth hogs to 512 Kbps ("Dial-Up"), 1 Mbps, 2 Mbps, or 5 Mbps.
- **Firewall Domain & Category Blacklist**: Drop DNS resolution and block domains (e.g. `tiktok.com`, `roblox.com`) across the whole network.
- **Emergency Kill Switch**: One-click "Freeze Network" halts all non-admin devices immediately.

### 5. 📱 Android Application & Mobile Ready
- **PWA (Progressive Web App)**: Open the dashboard on Google Chrome on Android and tap **"Install App"** / **"Add to Home Screen"** to run it as a full-screen native Android app.
- **Instant QR Pairing**: Scan the on-screen QR code with your phone camera to open the God Mode dashboard on mobile immediately.

---

## 🚀 How to Run

### Step 1: Start the Server
In your terminal, run:
```bash
python run.py
```

The launcher will automatically:
1. Detect your Wi-Fi interface and local IP address (e.g. `192.168.1.44`).
2. Start the FastAPI and WebSocket telemetry engine on port `8000`.
3. Open your default web browser to:
   - **Local Web Dashboard**: `http://localhost:8000`
   - **Android Mobile Access**: `http://<YOUR-LOCAL-IP>:8000`

---

## 📱 Opening on your Android Phone
1. Connect your Android phone to the same Wi-Fi network.
2. In the web dashboard, click **"ANDROID CONNECT"** (or switch to the **"Android Mobile App"** tab).
3. Scan the QR code with your phone's camera or open Chrome and type:
   ```
   http://192.168.1.44:8000
   ```
4. In Chrome menu (3 dots), tap **"Add to Home screen"** or **"Install application"**.
5. You now have the God Mode router commander installed directly on your Android phone!
