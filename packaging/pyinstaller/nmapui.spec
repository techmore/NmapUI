# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

# Resolve project paths from the spec file location so packaging does not
# depend on the caller's current working directory.
spec_dir = Path(__file__).resolve().parent
project_root = spec_dir.parents[1]
vulners_runtime_files = [
    (str(project_root / 'nmap-vulners' / 'LICENSE'), 'nmap-vulners'),
    (str(project_root / 'nmap-vulners' / 'vulners.nse'), 'nmap-vulners'),
    (str(project_root / 'nmap-vulners' / 'http-vulners-regex.nse'), 'nmap-vulners'),
    (str(project_root / 'nmap-vulners' / 'http-vulners-regex.json'), 'nmap-vulners'),
    (str(project_root / 'nmap-vulners' / 'http-vulners-paths.txt'), 'nmap-vulners'),
]

# Read version from VERSION file
version_file = project_root / "VERSION"
if version_file.exists():
    with open(version_file, "r") as f:
        app_version = f.read().strip()
else:
    app_version = "1.0.0"  # fallback

a = Analysis(
    [str(project_root / 'app.py')],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        # Include static assets
        (str(project_root / 'static'), 'static'),
        (str(project_root / 'templates'), 'templates'),
        (str(project_root / 'config'), 'config'),
        (str(project_root / 'VERSION'), '.'),
        (str(project_root / 'nmap-modern.xsl'), '.'),
        (str(project_root / 'nmap-pdf-olive-legacy.xsl'), '.'),
        # Include only the vulners runtime files required by the supported workflow
        *vulners_runtime_files,
    ],
    hiddenimports=[
        'engineio.async_drivers.threading',
        'flask',
        'flask_socketio',
        'jinja2',
        'playwright.async_api',
        'werkzeug',
        'xml.etree.ElementTree',
        'socketio',
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
        'LSMinimumSystemVersion': '13.0',
        'CFBundleShortVersionString': app_version,
        'CFBundleVersion': app_version,
    },
)
