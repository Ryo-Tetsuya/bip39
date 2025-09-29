#!/usr/bin/env bash
set -euo pipefail

binary_path="${1:-target/release/bip39}"
app_dir="${2:-target/release/BIP39 Tool.AppDir}"
app_name="${BIP39_APP_NAME:-BIP39 Tool}"
desktop_id="${BIP39_DESKTOP_ID:-dev.local.bip39-tool}"
executable_name="${BIP39_EXECUTABLE_NAME:-bip39}"

if [[ ! -f "$binary_path" ]]; then
  echo "Binary not found: $binary_path" >&2
  exit 1
fi

if [[ -z "$app_dir" || "$app_dir" == "/" || "$app_dir" == "." || "$app_dir" == ".." ]]; then
  echo "Refusing unsafe AppDir path: $app_dir" >&2
  exit 1
fi

rm -rf "$app_dir"
mkdir -p "$app_dir/usr/bin" "$app_dir/usr/share/applications"

cp "$binary_path" "$app_dir/usr/bin/$executable_name"
chmod 755 "$app_dir/usr/bin/$executable_name"

cat > "$app_dir/AppRun" <<APPRUN
#!/usr/bin/env bash
set -euo pipefail

APPDIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
exec "\$APPDIR/usr/bin/$executable_name" "\$@"
APPRUN
chmod 755 "$app_dir/AppRun"

cat > "$app_dir/$desktop_id.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=$app_name
Comment=Generate and recover BIP-39 backups
Exec=AppRun
Terminal=false
Categories=Utility;Finance;
StartupNotify=true
DESKTOP

cp "$app_dir/$desktop_id.desktop" "$app_dir/usr/share/applications/$desktop_id.desktop"

cat > "$app_dir/install-desktop-entry.sh" <<INSTALLER
#!/usr/bin/env bash
set -euo pipefail

APPDIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
desktop_dir="\${XDG_DATA_HOME:-\$HOME/.local/share}/applications"
desktop_file="\$desktop_dir/$desktop_id.desktop"

mkdir -p "\$desktop_dir"
cat > "\$desktop_file" <<DESKTOP
[Desktop Entry]
Type=Application
Name=$app_name
Comment=Generate and recover BIP-39 backups
Exec="\$APPDIR/AppRun"
Terminal=false
Categories=Utility;Finance;
StartupNotify=true
DESKTOP

chmod 644 "\$desktop_file"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "\$desktop_dir" >/dev/null 2>&1 || true
fi

echo "Installed desktop launcher: \$desktop_file"
INSTALLER
chmod 755 "$app_dir/install-desktop-entry.sh"

echo "Created Linux AppDir: $app_dir"
