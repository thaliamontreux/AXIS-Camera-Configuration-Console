# README.md

# ParamPilot — AXIS Camera Configurator

A technician-friendly Windows/Linux/macOS GUI for configuring **AXIS** network cameras via the **VAPIX** Parameter API — no vendor “recording unit” required.

- **Digest Auth over HTTP** (credentials never in URLs; password never logged)
- **Reads the camera’s XML schema** (`action=listdefinitions&listformat=xmlschema`) to auto-build the UI
- **Validates inputs** using real enum/range/boolean constraints from the device
- **Smart controls**: dropdowns, on/off + yes/no buttons, multi-value chips, read-only greying
- **Per-row updates**: one parameter at a time with status lights (red → blinking yellow → green)
- **Special editors**:
  - `root.Time.POSIXTimeZone`: split editor (zone, DST start, DST end) with recombine-on-update
  - `root.Image.OwnTimeFormat` and `root.Image.OwnDateFormat`: friendly presets + custom
- **Clean logging**: compact 4-line rolling debug (no passwords, no credentials in URLs)
- **UI for field work**: starts maximized, big scrollbars, alternating rows, tight alignment

> 💡 We publish pre-built installers/executables as we compile for each platform. Windows builds are provided now; Linux and macOS builds follow in Releases.

---

## Quick Start

### Option A — Windows (Prebuilt)
1. Download `ParamPilot.exe` from **Releases**.
2. Place `axis_param_keys_descriptions.csv` in the **same folder** as `ParamPilot.exe`.
3. Double-click to run (no install). The app launches maximized.

### Option B — Run from Source (All OS)
```bash
# 1) Create a virtual environment (recommended)
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

# 2) Install deps
pip install -r requirements.txt
# If no requirements.txt:
# pip install requests lxml

# 3) Run
python ParamPilot.py

## 𝗠𝗼𝗿𝗲 𝗶𝗻𝗳𝗼𝗿𝗺𝗮𝘁𝗶𝗼𝗻 𝗼𝗻 𝗔𝘅𝗶𝘀 𝗖𝗼𝗺𝗽𝗮𝗻𝗶𝗼𝗻 𝗖𝗮𝗺𝗲𝗿𝗮𝘀!  #################################################################
## For accessing it's RTSP Stream in 1080P you must include Axis-Orig-Sw=true to the end of the url.            #
##                                                                                                              #
## Capture a Still               Image: http://192.168.5.40/axis-cgi/mjpg/video.cgi?Axis-Orig-Sw=true           #
## Watch Live Video:             http://<camera url>/axis-cgi/mjpg/video.cgi?Axis-Orig-Sw=true                  #
## Connect to the RTSP Stream:   rtsp://<camera url>/axis-media/media.amp?Axis-Orig-Sw=true                     #
##                                                                                                              #
#################################################################################################################
