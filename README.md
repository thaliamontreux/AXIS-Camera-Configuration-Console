# 🎥 ParamPilot — AXIS Camera Configurator

> A **cross-platform** (Windows / Linux / macOS) GUI for configuring **AXIS** network cameras via the **VAPIX Parameter API** — no vendor recording unit required.  
> Designed for field technicians, installers, and integrators who need **speed, clarity, and reliability**.

---

## ✨ Key Features

- 🔐 **Secure** — Digest Auth over HTTP  
  Credentials are **never** exposed in URLs; passwords are **never** logged.
- 🧩 **Schema-driven UI** — Reads the camera’s XML schema  
  (`action=listdefinitions&listformat=xmlschema`) to build controls dynamically.
- ✅ **Input Validation** — Enum, range, and boolean constraints enforced directly from the device.
- 🎛 **Smart Controls**  
  - Dropdowns, toggle switches, yes/no buttons  
  - Multi-value chips with add/remove  
  - Read-only fields greyed out
- 🔄 **Per-row Updates** — Update a single parameter at a time with status lights:  
  `🔴 red → 🟡 blinking yellow → 🟢 green`
- 🛠 **Special Editors**  
  - `root.Time.POSIXTimeZone`: intuitive split editor for zone & DST with auto-recombine  
  - `root.Image.OwnTimeFormat` & `root.Image.OwnDateFormat`: presets + custom editor
- 📜 **Clean Logging** — Compact rolling debug (4 lines), never logs credentials
- 🖥 **UI for Field Work** — Starts maximized, big scrollbars, alternating row colors, tight alignment

---

## 🚀 Quick Start

### 🟩 Run from Source (All Platforms)
```bash
# 1) Create a virtual environment (recommended)
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

# 2) Install dependencies
pip install -r requirements.txt
# If missing:
# pip install requests lxml

# 3) Run the program
python ParamPilot.py

📂 Repository Programs
File	Purpose
ParamPilot.py	      Interactive GUI to configure Axis camera parameters via API
streamurl.py	      Generates ONVIF / RTSP connection URLs
cam-to-cam.py	      Clone configuration from one camera to another (selectable transfer)
firmwareupgrade.py	Firmware upgrade utility (🚧 in development — contributions welcome)
factory.py	        Restore a camera to factory defaults (wipe all settings)
📡 Axis Companion Camera Tips

⚡ Pro Tip: For 1080p RTSP streams, you must append
Axis-Orig-Sw=true at the end of the URL. If you dont include it the video will not start. 

📷 Capture Still Image:
http://192.168.5.40/axis-cgi/mjpg/video.cgi?Axis-Orig-Sw=true

🎬 Watch Live Video (MJPEG):
http://<camera-ip>/axis-cgi/mjpg/video.cgi?Axis-Orig-Sw=true

📡 RTSP Stream (H.264):
rtsp://<camera-ip>/axis-media/media.amp?Axis-Orig-Sw=true

📦 Installers & Releases

💡 Pre-built Windows executables are available now.
🐧 Linux & 🍏 macOS builds will be published in Releases
.

🤝 Contributing

Pull requests, bug reports, and feature suggestions are welcome!
Firmware upgrade helpers especially appreciated. 🚀

📜 License

© 2025 Thalia Sophia Montreux — Original Developer.
All modifications must continue to acknowledge this authorship
