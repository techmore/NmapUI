# Building and Packaging NmapUI for macOS

This guide explains how to build and package NmapUI for macOS distribution.

## Prerequisites

1. **Python Environment**: Python 3.8+ with virtual environment
2. **Dependencies**: Install build tools and dependencies
   ```bash
   pip install pyinstaller
   # Also ensure Nmap, ARP-Scan, wkhtmltopdf, xsltproc are available (for testing)
   ```

3. **macOS Development Tools**: Xcode command line tools
   ```bash
   xcode-select --install
   ```

## Building the Application Bundle

1. **Activate virtual environment** (if not already active)
   ```bash
   source venv/bin/activate
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run PyInstaller**
   ```bash
   pyinstaller --clean nmapui.spec
   ```

   This creates `dist/NmapUI.app` - a standalone macOS application bundle.

## Testing the Bundle

1. **Test startup**
   ```bash
   ./dist/NmapUI.app/Contents/MacOS/NmapUI --quick &
   sleep 5 && kill %1
   ```
   Check for successful startup messages.

2. **Full test** (optional)
   - Run the app and access http://localhost:5000
   - Test core functionality

## Creating Distribution Packages

### PKG Installer

```bash
pkgbuild --root ./dist --identifier com.techmore.nmapui --version 1.0.0 --install-location /Applications NmapUI.pkg
```

### DMG Disk Image

```bash
# Prepare contents
mkdir -p dmg_temp
cp -r dist/NmapUI.app dmg_temp/
cp NmapUI.pkg dmg_temp/
ln -s /Applications dmg_temp/Applications

# Create DMG
hdiutil create -volname "NmapUI Installer" -srcfolder dmg_temp -ov -format UDZO NmapUI.dmg

# Cleanup
rm -rf dmg_temp
```

## Automated Deployment

Use the provided deployment script:

```bash
./deploy.sh
```

This script will:
- Read version from `VERSION` file or generate timestamp-based version (v2026.1.9.12_01 format)
- Build the application bundle with PyInstaller
- Create PKG and DMG packages
- Create a GitHub release with the packages attached (requires `gh` CLI authentication)

The script automatically determines the version using the same method as the application.

## Code Signing and Notarization (Production)

For production releases, you should:

1. **Code Sign** the .app bundle
2. **Sign** the .pkg installer
3. **Notarize** with Apple for macOS 10.15+

Example code signing:
```bash
codesign --deep --force --verify --verbose --sign "Developer ID Application: Your Name" dist/NmapUI.app
```

## Troubleshooting

- **Bundle fails to start**: Check PyInstaller warnings in `build/nmapui/warn-nmapui.txt`
- **Missing modules**: Add to `hiddenimports` in `nmapui.spec`
- **Large bundle size**: Consider excluding unnecessary modules in the spec file

## File Structure After Build

```
dist/
├── NmapUI.app/          # macOS application bundle
└── ...

NmapUI.pkg               # Installer package
NmapUI.dmg               # Distribution disk image
```