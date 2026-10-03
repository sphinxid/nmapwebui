#!/usr/bin/env bash
# Fetch third-party browser assets into static/vendor so the app has no
# runtime CDN dependency. Requires curl and unzip (or python3). No Node.
set -euo pipefail

CHARTJS_VERSION="${CHARTJS_VERSION:-4.4.3}"
FONTAWESOME_VERSION="${FONTAWESOME_VERSION:-6.5.2}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/static/vendor"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$OUT/fontawesome/css" "$OUT/fontawesome/webfonts"

echo "chart.js $CHARTJS_VERSION"
curl -fsSL "https://cdn.jsdelivr.net/npm/chart.js@${CHARTJS_VERSION}/dist/chart.umd.js" -o "$OUT/chart.umd.js"

echo "font awesome $FONTAWESOME_VERSION"
ZIP="$TMP/fa.zip"
curl -fsSL "https://github.com/FortAwesome/Font-Awesome/releases/download/${FONTAWESOME_VERSION}/fontawesome-free-${FONTAWESOME_VERSION}-web.zip" -o "$ZIP"
if command -v unzip >/dev/null; then
  unzip -q "$ZIP" -d "$TMP"
else
  python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$ZIP" "$TMP"
fi
FA="$TMP/fontawesome-free-${FONTAWESOME_VERSION}-web"
cp "$FA/css/all.min.css" "$OUT/fontawesome/css/all.min.css"
for f in fa-solid-900 fa-regular-400 fa-brands-400; do
  cp "$FA/webfonts/$f.woff2" "$FA/webfonts/$f.ttf" "$OUT/fontawesome/webfonts/"
done

echo "vendored into static/vendor"
