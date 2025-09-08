#!/usr/bin/env python3
# axis_onvif_rtsp_tool.py
#
# Axis ONVIF/RTSP Explorer & Player (HTTP only, Digest auth; no HTTPS)
# - Appends Axis-Orig-Sw=true to ALL RTSP URLs (ONVIF and Axis templates)
# - Lists ONVIF profiles; fetches Stream URI & Snapshot URI (when ONVIF enabled)
# - Falls back to Axis RTSP/Snapshot URLs if ONVIF faults
# - Plays RTSP via embedded VLC
# - Copy-to-clipboard buttons
#
# Deps (Windows):
#   pip install pyqt6 onvif-zeep python-vlc requests
# Run:
#   python axis_onvif_rtsp_tool.py

import os
import sys
import traceback
from typing import Optional, Dict, Any
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QGuiApplication, QIcon
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QGridLayout, QHBoxLayout, QVBoxLayout, QComboBox, QTextEdit, QGroupBox,
    QSplitter, QCheckBox, QSlider, QMessageBox
)

import vlc
from onvif import ONVIFCamera

APP_TITLE = "Axis ONVIF/RTSP Explorer & Player (HTTP only)"
DEFAULT_PORT = 80
DEFAULT_USER = "root"
DEFAULT_PASS = "root"


def copy_to_clipboard(text: str):
    QGuiApplication.clipboard().setText(text or "")


def short_exc(e: BaseException) -> str:
    return f"{e.__class__.__name__}: {e}"


def _append_axis_orig_sw(url: str) -> str:
    """
    Ensure RTSP URL ends with Axis-Orig-Sw=true (as a query param).
    Idempotent; preserves existing params and fragments.
    """
    if not url or not isinstance(url, str):
        return url
    try:
        parts = urlsplit(url)
        # Only modify RTSP URLs
        if parts.scheme.lower() != "rtsp":
            return url
        q = parse_qsl(parts.query, keep_blank_values=True)
        # Check if already present (case-insensitive key match)
        if not any(k.lower() == "axis-orig-sw" for k, _ in q):
            q.append(("Axis-Orig-Sw", "true"))
        new_query = urlencode(q)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    except Exception:
        # If parsing fails for some odd reason, append conservatively
        sep = "&" if ("?" in url) else "?"
        if "Axis-Orig-Sw=" not in url and "axis-orig-sw=" not in url.lower():
            return f"{url}{sep}Axis-Orig-Sw=true"
        return url


class OnvifFetcher(QThread):
    fetched = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, ip: str, username: str, password: str, port: int = DEFAULT_PORT, profile_token: Optional[str] = None):
        super().__init__()
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.profile_token = profile_token

    def _make_camera(self) -> ONVIFCamera:
        try:
            return ONVIFCamera(self.ip, self.port, self.username, self.password)
        except TypeError:
            pass
        try:
            return ONVIFCamera(self.ip, self.port, self.username, self.password, wsdl_dir=None)
        except TypeError:
            pass
        return ONVIFCamera(self.ip, self.port, self.username, self.password, wsdl=None)

    def run(self):
        try:
            cam = self._make_camera()
            dev_mgmt = cam.create_devicemgmt_service()
            media = cam.create_media_service()

            info: Dict[str, Any] = {}
            try:
                di = dev_mgmt.GetDeviceInformation()
                info["device_information"] = {
                    "Manufacturer": getattr(di, "Manufacturer", ""),
                    "Model": getattr(di, "Model", ""),
                    "FirmwareVersion": getattr(di, "FirmwareVersion", ""),
                    "SerialNumber": getattr(di, "SerialNumber", ""),
                    "HardwareId": getattr(di, "HardwareId", ""),
                }
            except Exception:
                info["device_information"] = {}

            profiles = media.GetProfiles() or []
            profs = [{"name": getattr(p, "Name", "") or "", "token": getattr(p, "token", "") or ""} for p in profiles]
            if not profs:
                raise RuntimeError("No ONVIF media profiles found on the device.")

            if self.profile_token and any(p["token"] == self.profile_token for p in profs):
                chosen_token = self.profile_token
            else:
                chosen_token = profs[0]["token"]

            req = {
                "StreamSetup": {"Stream": "RTP-Unicast", "Transport": {"Protocol": "RTSP"}},
                "ProfileToken": chosen_token
            }
            onvif_rtsp = ""
            try:
                stream_uri = media.GetStreamUri(req)
                onvif_rtsp = getattr(stream_uri, "Uri", "") or ""
            except Exception:
                onvif_rtsp = ""

            # Append Axis-Orig-Sw=true to ONVIF RTSP URL (if present)
            onvif_rtsp = _append_axis_orig_sw(onvif_rtsp)

            snapshot_uri = ""
            try:
                snap = media.GetSnapshotUri({"ProfileToken": chosen_token})
                snapshot_uri = getattr(snap, "Uri", "") or ""
            except Exception:
                snapshot_uri = ""

            out = {
                "profiles": profs,
                "selected_profile_token": chosen_token,
                "device_information": info.get("device_information", {}),
                "onvif_rtsp_uri": onvif_rtsp,
                "snapshot_uri": snapshot_uri,
            }
            self.fetched.emit(out)

        except Exception as e:
            # ONVIF failed: provide Axis fallbacks so UI still works
            ip = self.ip
            axis_rtsp_h264 = _append_axis_orig_sw(f"rtsp://{ip}/axis-media/media.amp?videocodec=h264")
            axis_rtsp_mjpeg = _append_axis_orig_sw(f"rtsp://{ip}/axis-media/media.amp?videocodec=motion-jpeg")
            axis_snapshot = f"http://{ip}/axis-cgi/jpg/image.cgi"
            self.fetched.emit({
                "profiles": [],
                "selected_profile_token": "",
                "device_information": {},
                "onvif_rtsp_uri": "",
                "snapshot_uri": axis_snapshot,
                "_fallback_axis": {
                    "axis_rtsp_h264": axis_rtsp_h264,
                    "axis_rtsp_mjpeg": axis_rtsp_mjpeg,
                    "error": f"{short_exc(e)}\n{traceback.format_exc(limit=5)}",
                }
            })


class PlayerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.instance = vlc.Instance()
        self.mediaplayer = self.instance.media_player_new()

        self.video_area = QWidget(self)
        self.video_area.setObjectName("video_area")
        self.video_area.setStyleSheet("#video_area { background: #111; }")

        self.play_btn = QPushButton("Play")
        self.stop_btn = QPushButton("Stop")
        self.mute_chk = QCheckBox("Mute")
        self.volume = QSlider(Qt.Orientation.Horizontal)
        self.volume.setRange(0, 100)
        self.volume.setValue(100)

        ctl = QHBoxLayout()
        ctl.addWidget(self.play_btn)
        ctl.addWidget(self.stop_btn)
        ctl.addStretch(1)
        ctl.addWidget(self.mute_chk)
        ctl.addWidget(QLabel("Volume:"))
        ctl.addWidget(self.volume)

        layout = QVBoxLayout(self)
        layout.addWidget(self.video_area, 1)
        layout.addLayout(ctl)

        self.play_btn.clicked.connect(self._play_clicked)
        self.stop_btn.clicked.connect(self.stop)
        self.mute_chk.stateChanged.connect(self._toggle_mute)
        self.volume.valueChanged.connect(self._set_volume)

        self.current_url = ""

    def set_url(self, url: str):
        self.current_url = url or ""

    def _play_clicked(self):
        if not self.current_url:
            QMessageBox.warning(self, "No URL", "No media URL to play.")
            return
        self.play(self.current_url)

    def play(self, url: str):
        try:
            media = self.instance.media_new(url, ":no-video-title-show")
            self.mediaplayer.set_media(media)
            if sys.platform.startswith("win"):
                self.mediaplayer.set_hwnd(int(self.video_area.winId()))
            else:
                self.mediaplayer.set_xwindow(int(self.video_area.winId()))
            self.mediaplayer.play()
        except Exception as e:
            QMessageBox.critical(self, "VLC Error", f"Failed to play: {e}")

    def stop(self):
        try:
            self.mediaplayer.stop()
        except Exception:
            pass

    def _toggle_mute(self, state):
        try:
            self.mediaplayer.audio_set_mute(bool(state))
        except Exception:
            pass

    def _set_volume(self, val):
        try:
            self.mediaplayer.audio_set_volume(int(val))
        except Exception:
            pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        try:
            self.setWindowIcon(QIcon.fromTheme("camera-video"))
        except Exception:
            pass
        self.resize(1220, 760)

        left = QWidget()
        lg = QGridLayout(left)
        r = 0

        lg.addWidget(QLabel("Camera IP (HTTP):"), r, 0)
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("e.g., 192.168.5.40")
        lg.addWidget(self.ip_edit, r, 1, 1, 2)

        r += 1
        lg.addWidget(QLabel("Username:"), r, 0)
        self.user_edit = QLineEdit(DEFAULT_USER)
        lg.addWidget(self.user_edit, r, 1, 1, 2)

        r += 1
        lg.addWidget(QLabel("Password:"), r, 0)
        self.pass_edit = QLineEdit(DEFAULT_PASS)
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        lg.addWidget(self.pass_edit, r, 1, 1, 2)

        r += 1
        self.connect_btn = QPushButton("Connect (ONVIF over HTTP)")
        lg.addWidget(self.connect_btn, r, 0, 1, 3)

        r += 1
        lg.addWidget(QLabel("ONVIF Profile:"), r, 0)
        self.profile_combo = QComboBox()
        lg.addWidget(self.profile_combo, r, 1, 1, 2)

        url_box = QGroupBox("URLs (copy/paste)")
        url_layout = QGridLayout(url_box)

        def url_row(row: int, label: str):
            lab = QLabel(label)
            edit = QLineEdit()
            btn = QPushButton("Copy")
            url_layout.addWidget(lab, row, 0)
            url_layout.addWidget(edit, row, 1)
            url_layout.addWidget(btn, row, 2)
            return edit, btn

        u = 0
        self.onvif_rtsp_edit, self.onvif_rtsp_copy = url_row(u, "ONVIF RTSP URI:")
        u += 1
        self.snapshot_edit, self.snapshot_copy = url_row(u, "ONVIF Snapshot URI:")
        u += 1
        self.axis_rtsp_h264_edit, self.axis_rtsp_h264_copy = url_row(u, "Axis RTSP (H.264):")
        u += 1
        self.axis_rtsp_mjpeg_edit, self.axis_rtsp_mjpeg_copy = url_row(u, "Axis RTSP (MJPEG):")

        r += 1
        lg.addWidget(url_box, r, 0, 1, 3)

        r += 1
        play_box = QGroupBox("Playback Options")
        pb = QGridLayout(play_box)

        self.embed_creds_chk = QCheckBox("Embed credentials (user:pass@host) in RTSP")
        self.embed_creds_chk.setChecked(True)
        pb.addWidget(self.embed_creds_chk, 0, 0, 1, 3)

        self.play_onvif_btn = QPushButton("▶ Play ONVIF RTSP")
        self.play_axis_btn = QPushButton("▶ Play Axis RTSP (H.264)")
        pb.addWidget(self.play_onvif_btn, 1, 0, 1, 2)
        pb.addWidget(self.play_axis_btn, 1, 2, 1, 1)

        lg.addWidget(play_box, r, 0, 1, 3)

        r += 1
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        lg.addWidget(self.log, r, 0, 1, 3)

        self.player = PlayerWidget()

        split = QSplitter()
        split.addWidget(left)
        split.addWidget(self.player)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        self.setCentralWidget(split)

        self.connect_btn.clicked.connect(self.on_connect)
        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed)

        self.onvif_rtsp_copy.clicked.connect(lambda: copy_to_clipboard(self.onvif_rtsp_edit.text()))
        self.snapshot_copy.clicked.connect(lambda: copy_to_clipboard(self.snapshot_edit.text()))
        self.axis_rtsp_h264_copy.clicked.connect(lambda: copy_to_clipboard(self.axis_rtsp_h264_edit.text()))
        self.axis_rtsp_mjpeg_copy.clicked.connect(lambda: copy_to_clipboard(self.axis_rtsp_mjpeg_edit.text()))

        self.play_onvif_btn.clicked.connect(self.play_onvif)
        self.play_axis_btn.clicked.connect(self.play_axis)

        self.current_profiles = []
        self.selected_profile_token: Optional[str] = None

    def log_msg(self, msg: str):
        self.log.append(msg)

    def on_connect(self):
        ip = (self.ip_edit.text() or "").strip()
        user = (self.user_edit.text() or "").strip()
        pwd = (self.pass_edit.text() or "").strip()
        if not ip:
            QMessageBox.warning(self, "Missing IP", "Please enter the camera IP.")
            return
        self.log_msg(f"Connecting to ONVIF over http://{ip}:{DEFAULT_PORT} ...")

        self.connect_btn.setEnabled(False)
        self.fetcher = OnvifFetcher(ip, user, pwd, port=DEFAULT_PORT, profile_token=self.selected_profile_token)
        self.fetcher.fetched.connect(self.on_onvif_fetched)
        self.fetcher.failed.connect(self.on_onvif_failed)
        self.fetcher.start()

    def on_onvif_failed(self, err: str):
        self.connect_btn.setEnabled(True)
        self.log_msg(f"<span style='color:#c33'>ERROR:</span><pre>{err}</pre>")
        QMessageBox.critical(self, "ONVIF Error", err)

    def on_onvif_fetched(self, data: dict):
        self.connect_btn.setEnabled(True)

        # Profiles (may be empty if fallback used)
        self.current_profiles = data.get("profiles", [])
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        for p in self.current_profiles:
            name = p.get("name") or "(unnamed)"
            token = p.get("token") or ""
            self.profile_combo.addItem(f"{name} [{token}]", token)
        self.profile_combo.blockSignals(False)

        tok = data.get("selected_profile_token")
        if tok:
            idx = self.profile_combo.findData(tok)
            if idx >= 0:
                self.profile_combo.setCurrentIndex(idx)
            self.selected_profile_token = tok

        # ONVIF RTSP (already has Axis-Orig-Sw=true from fetcher)
        onvif_rtsp = data.get("onvif_rtsp_uri", "") or ""
        snapshot = data.get("snapshot_uri", "") or ""
        self.onvif_rtsp_edit.setText(onvif_rtsp)
        self.snapshot_edit.setText(snapshot)

        # Axis RTSP convenience URLs with Axis-Orig-Sw=true
        ip = (self.ip_edit.text() or "").strip()
        user = (self.user_edit.text() or "").strip()
        pwd = (self.pass_edit.text() or "").strip()
        auth_prefix = f"{user}:{pwd}@" if (self.embed_creds_chk.isChecked() and user and pwd) else ""

        axis_rtsp_h264 = _append_axis_orig_sw(f"rtsp://{auth_prefix}{ip}/axis-media/media.amp?videocodec=h264")
        axis_rtsp_mjpeg = _append_axis_orig_sw(f"rtsp://{auth_prefix}{ip}/axis-media/media.amp?videocodec=motion-jpeg")

        fb = data.get("_fallback_axis")
        if fb:
            self.log_msg("<b>ONVIF call failed</b>; using Axis fallback URLs. "
                         "Enable ONVIF and/or create an ONVIF user to restore ONVIF features.")
        self.axis_rtsp_h264_edit.setText(axis_rtsp_h264)
        self.axis_rtsp_mjpeg_edit.setText(axis_rtsp_mjpeg)

        di = data.get("device_information", {})
        if di:
            self.log_msg(f"Device: {di.get('Manufacturer','')} {di.get('Model','')} | FW: {di.get('FirmwareVersion','')} | SN: {di.get('SerialNumber','')}")
        self.log_msg("URLs populated.")

    def on_profile_changed(self, idx: int):
        tok = self.profile_combo.itemData(idx)
        if tok:
            self.selected_profile_token = tok
            self.log_msg(f"Selected profile token: {tok}")

    def _prepare_url_for_play(self, url: str) -> str:
        if not url:
            return ""
        # Ensure Axis-Orig-Sw=true is present even if user pasted their own URL
        url = _append_axis_orig_sw(url)
        if not self.embed_creds_chk.isChecked():
            return url
        user = (self.user_edit.text() or "").strip()
        pwd = (self.pass_edit.text() or "").strip()
        if not user or not pwd:
            return url
        if "://" in url and "@" not in url:
            scheme, rest = url.split("://", 1)
            return f"{scheme}://{user}:{pwd}@{rest}"
        return url

    def play_onvif(self):
        url = self._prepare_url_for_play((self.onvif_rtsp_edit.text() or "").strip())
        if not url:
            QMessageBox.warning(self, "No URL", "No ONVIF RTSP URL available.")
            return
        self.log_msg(f"Playing ONVIF RTSP: {url}")
        self.player.set_url(url)
        self.player.play(url)

    def play_axis(self):
        url = self._prepare_url_for_play((self.axis_rtsp_h264_edit.text() or "").strip())
        if not url:
            QMessageBox.warning(self, "No Axis RTSP URL available.")
            return
        self.log_msg(f"Playing Axis RTSP: {url}")
        self.player.set_url(url)
        self.player.play(url)


def main():
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
    os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
