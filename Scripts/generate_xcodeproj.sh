#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=Scripts/bootstrap_runner_env.sh
source "$ROOT/Scripts/bootstrap_runner_env.sh"
cd "$ROOT"

if command -v tuist >/dev/null 2>&1; then
  tuist generate --path "$ROOT"
  python3 - "$ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
last_upgrade_version = "2650"
project_path = root / "better-auth-swift.xcodeproj" / "project.pbxproj"
project = project_path.read_text()
if "LastUpgradeCheck" not in project:
    project = project.replace(
        "\t\t\tattributes = {\n",
        f"\t\t\tattributes = {{\n\t\t\t\tLastUpgradeCheck = {last_upgrade_version};\n",
        1,
    )
else:
    project = re.sub(
        r"\t*LastUpgradeCheck = \d+;",
        f"\t\t\t\tLastUpgradeCheck = {last_upgrade_version};",
        project,
        count=1,
    )
project_path.write_text(project)

for scheme_path in [
    *root.glob("*.xcodeproj/xcshareddata/xcschemes/*.xcscheme"),
    *root.glob("*.xcworkspace/xcshareddata/xcschemes/*.xcscheme"),
]:
    scheme = scheme_path.read_text()
    scheme = re.sub(
        r'LastUpgradeVersion = "\d+"',
        f'LastUpgradeVersion = "{last_upgrade_version}"',
        scheme,
        count=1,
    )
    scheme_path.write_text(scheme)
PY
  exit 0
fi

echo "tuist is required to generate the Xcode project. Install with: curl -Ls https://install.tuist.io | bash" >&2
exit 1
