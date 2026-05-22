#!/usr/bin/env bash
set -euo pipefail
PKG="${1:-}"
EXPECTED_VERSION="${2:-}"
if [ -z "$PKG" ] || [ -z "$EXPECTED_VERSION" ]; then
  echo "用法：bash tools/release_check.sh <package.tar.gz> <version>"
  exit 1
fi
EXPECTED_NUM="${EXPECTED_VERSION#v}"
EXPECTED_TAG="v${EXPECTED_NUM}"
[ -f "$PKG" ] || { echo "❌ 文件不存在：$PKG"; exit 1; }
BASENAME="$(basename "$PKG")"
case "$BASENAME" in
  wg-webui-app-${EXPECTED_TAG}.tar.gz) EXPECTED_DIR="wg-webui-app-${EXPECTED_TAG}"; TYPE="app" ;;
  wg-webui-${EXPECTED_TAG}.tar.gz) EXPECTED_DIR="wg-webui-${EXPECTED_TAG}"; TYPE="full" ;;
  wg-webui-deploy-${EXPECTED_TAG}.tar.gz) EXPECTED_DIR="wg-webui-deploy-${EXPECTED_TAG}"; TYPE="deploy" ;;
  wg-webui-bundle-${EXPECTED_TAG}.tar.gz) EXPECTED_DIR="wg-webui-bundle-${EXPECTED_TAG}"; TYPE="bundle" ;;
  *) echo "❌ 文件名不一致或类型不支持：$BASENAME"; exit 1 ;;
esac
SIZE=$(stat -c%s "$PKG" 2>/dev/null || wc -c < "$PKG")
if [ "$SIZE" -lt 4096 ]; then echo "❌ 包大小异常，疑似空包：${SIZE} bytes"; exit 1; fi
tar -tzf "$PKG" >/dev/null || { echo "❌ 不是有效 tar.gz"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
tar -xzf "$PKG" -C "$TMP"
[ -d "$TMP/$EXPECTED_DIR" ] || { echo "❌ 顶层目录错误：期望 $EXPECTED_DIR/"; find "$TMP" -maxdepth 2 -type d | sed "s#$TMP/##"; exit 1; }
cd "$TMP/$EXPECTED_DIR"
case "$TYPE" in
  app|full)
    if [ -d bundle ]; then
      required=(wg-webui.sh VERSION README.md manifest.json bundle/app/app.py bundle/app/requirements.txt bundle/app/core/__init__.py bundle/app/core/networks.py bundle/app/core/security.py bundle/app/templates/index.html bundle/app/static/css/app.css bundle/app/static/js/app.js bundle/VERSION bundle/PACKAGE_TYPE bundle/README.md bundle/SECURITY.md bundle/wg-webui.sh bundle/install.sh bundle/upgrade.sh bundle/uninstall.sh bundle/doctor.sh bundle/config/config.json.sample bundle/scripts/install.sh bundle/scripts/upgrade.sh bundle/scripts/uninstall.sh bundle/scripts/doctor.sh bundle/tools/repair_allowedips.py bundle/tools/sync_allowedips.py bundle/tools/repair_wg_nat.py bundle/tools/cleanup.py bundle/tools/release_check.sh bundle/tools/build_release.py bundle/tools/wireguard-userspace-compat-v0.5.0.tar.gz bundle/docs/INSTALL.md bundle/docs/CONFIGURATION.md bundle/docs/OPERATIONS.md)
    else
      required=(app/app.py app/requirements.txt app/core/__init__.py app/core/networks.py app/core/security.py app/templates/index.html app/static/css/app.css app/static/js/app.js install.sh upgrade.sh uninstall.sh doctor.sh VERSION PACKAGE_TYPE README.md SECURITY.md config/config.json.sample scripts/install.sh scripts/upgrade.sh scripts/uninstall.sh scripts/doctor.sh tools/repair_allowedips.py tools/sync_allowedips.py tools/repair_wg_nat.py tools/cleanup.py tools/release_check.sh tools/build_release.py tools/wireguard-userspace-compat-v0.5.0.tar.gz docs/INSTALL.md docs/CONFIGURATION.md docs/OPERATIONS.md)
    fi
    ;;
  deploy)
    required=(install.sh upgrade.sh doctor.sh uninstall.sh VERSION PACKAGE_TYPE config.json.sample README.md tools/release_check.sh)
    ;;
  bundle)
    required=(README.md app/wg-webui-app-${EXPECTED_TAG}.tar.gz deploy/wg-webui-deploy-${EXPECTED_TAG}.tar.gz transition/wg-webui-${EXPECTED_TAG}.tar.gz)
    ;;
esac
for f in "${required[@]}"; do [ -f "$f" ] || { echo "❌ 缺少必要文件：$f"; exit 1; }; done
if [ -f VERSION ]; then
  VERSION_FILE="$(tr -d '[:space:]' < VERSION)"
  [ "$VERSION_FILE" = "$EXPECTED_TAG" ] || [ "$VERSION_FILE" = "$EXPECTED_NUM" ] || { echo "❌ VERSION 不一致：期望 $EXPECTED_TAG，实际 $VERSION_FILE"; exit 1; }
fi
if [ -f bundle/app/app.py ]; then grep -q "APP_VERSION = \"${EXPECTED_TAG}\"" bundle/app/app.py || { echo "❌ bundle/app/app.py APP_VERSION 未更新为 ${EXPECTED_TAG}"; exit 1; }; elif [ -f app/app.py ]; then grep -q "APP_VERSION = \"${EXPECTED_TAG}\"" app/app.py || { echo "❌ app/app.py APP_VERSION 未更新为 ${EXPECTED_TAG}"; exit 1; }; elif [ -f app.py ]; then grep -q "APP_VERSION = \"${EXPECTED_TAG}\"" app.py || { echo "❌ app.py APP_VERSION 未更新为 ${EXPECTED_TAG}"; exit 1; }; fi
if find . \( -name '__pycache__' -o -name '.git' -o -name '.pytest_cache' -o -name '*.pyc' \) | grep -q .; then echo "❌ 包内包含不应发布的缓存或 Git 目录"; exit 1; fi
COUNT="$(find . -type f | wc -l | awk '{print $1}')"
if [ "$TYPE" = "bundle" ]; then MIN_COUNT=4; else MIN_COUNT=8; fi
if [ "$COUNT" -lt "$MIN_COUNT" ]; then echo "❌ 文件数量异常，可能是空包或打包错误"; exit 1; fi
echo "✅ 发布包自检通过：$BASENAME"
echo "类型：$TYPE"
echo "版本：$EXPECTED_TAG"
echo "大小：$SIZE bytes"
echo "文件数：$COUNT"
