#!/usr/bin/env bash
set -euo pipefail

binary_path="${1:-target/release/bip39}"
app_path="${2:-target/release/BIP39 Tool.app}"
bundle_name="${BIP39_BUNDLE_NAME:-BIP39 Tool}"
bundle_id="${BIP39_BUNDLE_ID:-dev.local.bip39-tool}"
version="${BIP39_BUNDLE_VERSION:-0.1.0}"
executable_name="bip39"

if [[ ! -f "$binary_path" ]]; then
  echo "Binary not found: $binary_path" >&2
  exit 1
fi

rm -rf "$app_path"
mkdir -p "$app_path/Contents/MacOS" "$app_path/Contents/Resources"

cp "$binary_path" "$app_path/Contents/MacOS/$executable_name"
chmod 755 "$app_path/Contents/MacOS/$executable_name"

cat > "$app_path/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>${executable_name}</string>
  <key>CFBundleIdentifier</key>
  <string>${bundle_id}</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>${bundle_name}</string>
  <key>CFBundleDisplayName</key>
  <string>${bundle_name}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${version}</string>
  <key>CFBundleVersion</key>
  <string>${version}</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
</dict>
</plist>
PLIST

if command -v plutil >/dev/null 2>&1; then
  plutil -lint "$app_path/Contents/Info.plist" >/dev/null
fi

if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$app_path" >/dev/null
fi

echo "Created $app_path"
