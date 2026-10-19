#!/usr/bin/env bash
# Install the Tomey Gun desktop/menu entry for an already configured checkout.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[[ -f .env && -d node_modules ]] || { echo "Run setup-and-run.sh --verify-only first." >&2; exit 2; }
command -v systemctl >/dev/null 2>&1 || { echo "systemctl is required." >&2; exit 2; }
systemctl --user cat autohack.service >/dev/null || { echo "Run bash scripts/install-user-service.sh first." >&2; exit 2; }
python3 - "$ROOT" <<'PY'
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
home = Path.home()
data = Path(os.environ.get('XDG_DATA_HOME') or home / '.local/share')
applications = data / 'applications'
icon = data / 'icons/hicolor/256x256/apps/tomey-gun.png'
applications.mkdir(parents=True, exist_ok=True)
icon.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(root / 'assets/desktop/constanzo.png', icon)
icon.chmod(0o644)
# Desktop-entry escaping and Exec quoting are different: apply both to paths.
def value(text):
    return str(text).replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r')
def argument(text):
    escaped = str(text).replace('%', '%%')
    for char in ('\\', '"', '`', '$'):
        escaped = escaped.replace(char, '\\' + char)
    return value('"' + escaped + '"')

entry = '\n'.join([
    '[Desktop Entry]', 'Type=Application', 'Version=1.0',
    'Name=Tomey Gun', 'Comment=Open the local Tomey Gun dashboard',
    'Exec=/usr/bin/env bash ' + argument(root / 'scripts/launch-desktop.sh'),
    'Icon=' + value(icon), 'Terminal=false', 'StartupNotify=true',
    'StartupWMClass=TomeyGun', 'Categories=Development;', 'Actions=Stop;', '',
    '[Desktop Action Stop]', 'Name=Stop Tomey Gun',
    'Exec=/usr/bin/systemctl --user stop autohack.service', '',
])
menu = applications / 'tomey-gun.desktop'
menu.write_text(entry)
menu.chmod(0o755)
desktop = None
if shutil.which('xdg-user-dir'):
    result = subprocess.run(['xdg-user-dir', 'DESKTOP'], capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip():
        desktop = Path(result.stdout.strip())
if desktop is None:
    desktop = home / 'Desktop'
# An XDG desktop equal to HOME conventionally means desktop icons are disabled.
if desktop.resolve() != home.resolve():
    desktop.mkdir(parents=True, exist_ok=True)
    shortcut = desktop / 'Tomey-Gun.desktop'
    shutil.copyfile(menu, shortcut)
    shortcut.chmod(0o755)
    if shutil.which('gio'):
        subprocess.run(['gio', 'set', str(shortcut), 'metadata::trusted', 'true'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
if shutil.which('update-desktop-database'):
    subprocess.run(['update-desktop-database', str(applications)], check=False)
print('Tomey Gun installed in your application menu.')
if desktop.resolve() != home.resolve():
    print('Desktop shortcut: ' + str(desktop / 'Tomey-Gun.desktop'))
print('If the desktop asks, right-click the icon and choose Allow Launching.')
PY
