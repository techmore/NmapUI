# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path

# Get the directory containing the spec file (current working directory when pyinstaller is run)
spec_dir = Path.cwd()

# Read version from VERSION file
version_file = spec_dir / "VERSION"
if version_file.exists():
    with open(version_file, "r") as f:
        app_version = f.read().strip()
else:
    app_version = "1.0.0"  # fallback

a = Analysis(
    ['app.py'],
    pathex=[str(spec_dir)],
    binaries=[],
    datas=[
        # Include static assets
        (str(spec_dir / 'static'), 'static'),
        (str(spec_dir / 'templates'), 'templates'),
        # Include nmap-vulners script if present
        (str(spec_dir / 'nmap-vulners'), 'nmap-vulners'),
    ],
    hiddenimports=[
        'engineio.async_drivers.threading',
        'eventlet',
        'flask',
        'flask_socketio',
        'gevent',
        'geventwebsocket',
        'jinja2',
        'werkzeug',
        'weasyprint',
        'xml.etree.ElementTree',
        'socketio',
        'ipaddress',
        'pathlib',
        'subprocess',
        'threading',
        'datetime',
        'json',
        'logging',
        're',
        'shutil',
        'tempfile',
        'urllib.request',
        'urllib.parse',
        'platform',
        'os',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',  # Not needed for server-only app
        'matplotlib',  # Not used
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NmapUI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,  # Keep console for debugging, can change to False later
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=app_version,  # Set version info for the executable
)

app = BUNDLE(
    exe,
    a.binaries,
    a.datas,
    name='NmapUI.app',
    icon=None,  # Can add an icon later
    bundle_identifier='com.techmore.nmapui',
    version=app_version,
    info_plist={
        'NSHighResolutionCapable': True,
        'LSMinimumSystemVersion': '10.13.0',
        'CFBundleShortVersionString': app_version,
        'CFBundleVersion': app_version,
    },
)