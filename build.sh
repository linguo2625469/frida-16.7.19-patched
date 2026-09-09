#!/usr/bin/env bash
# ============================================================================
# build.sh — 构建 wmpdbg 修复版 frida-server 16.7.19 (Android)
#
# 背景(为什么需要修复版):
#   官方 frida 16.x 的 frida-server 在新版 ART 上会触发【整机软重启】:
#   frida-core 的线程数隐藏器(cloak) hook libart.so 的 read, 而 2024-11 起的
#   ART(Google Play 系统更新推送的 ART 模块 / Android 15+/16 固件)把线程统计
#   代码挪到了 libartbase.so —— hook 错目标即崩。见 frida#3365(官方 17.2.13
#   才修复, 16.x 不再发版)。我们锁 16.7.19(与客户端 npm frida 协议一致),
#   因此自建补丁版:
#     补丁1: cloak 改为优先 libartbase.so/__read_chk(修整机重启, 必装)
#     补丁2: frida-java-bridge GC 钩子符号找不到时模式扫描兜底(修 Android
#            15/16 上 Java hook GC 崩溃, 异常时退化为官方行为)
#
# 产物(本脚本不改任何协议字符串/端口/D-Bus 名, 与官方 16.7.19 二进制可互换,
# 客户端无需任何改动 —— 也因此必须靠 SHA256 区分设备上装的是官方版还是修复版):
#   dist/frida-server-16.7.19-android-<arch>      裸二进制(未压缩)
#   dist/SHA256SUMS                                哈希清单
#   dist/frida-patched-manifest.json               给 App 端 provisioner 用的清单
#
# 环境: Linux(GitHub Actions ubuntu-latest 已验证依赖见 .github/workflows/build.yml;
#       本地需 Ubuntu/Debian + git/python3/基本构建工具; Windows 请用 WSL2)。
# 可选环境变量:
#   ANDROID_NDK_ROOT  指向 Android NDK(部分环境 releng 需要; CI 里已装 r25b)
#
# 用法:
#   bash build.sh                # 默认构建 android-arm64
#   bash build.sh android-arm64 android-arm   # 同时构建 32 位 arm(老设备)
# ============================================================================
set -euo pipefail

FRIDA_VERSION="16.7.19"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$SCRIPT_DIR/work"
FRIDA_DIR="$WORK/frida"
DIST="$SCRIPT_DIR/dist"
TARGETS=("$@")
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=("android-arm64")

arch_of() {
  # android-arm64 -> arm64 ; android-arm -> arm
  echo "${1#android-}"
}

echo "===== [1/5] 拉取 frida ${FRIDA_VERSION} 源码(tag 固定, 保证与 npm frida ${FRIDA_VERSION} 协议一致) ====="
mkdir -p "$WORK" "$DIST"
if [ ! -d "$FRIDA_DIR/.git" ]; then
  git clone --depth 1 --branch "$FRIDA_VERSION" https://github.com/frida/frida.git "$FRIDA_DIR"
fi
cd "$FRIDA_DIR"
for sub in frida-core frida-gum; do
  d="$FRIDA_DIR/subprojects/$sub"
  if [ ! -d "$d/.git" ]; then
    git clone --depth 1 --branch "$FRIDA_VERSION" "https://github.com/frida/$sub.git" "$d"
  fi
done
if [ ! -f "$FRIDA_DIR/releng/meson/meson.py" ]; then
  (git submodule update --init --depth 1 releng) || \
    git clone --depth 1 https://github.com/frida/releng.git "$FRIDA_DIR/releng"
fi

echo "===== [2/5] 应用补丁 ====="
# 补丁1: frida-core cloak 修复(整机软重启根因)
git -C subprojects/frida-core apply --check "$SCRIPT_DIR/patches/0001-frida-core-cloak-support-libartbase.patch" 2>/dev/null || true
if git -C subprojects/frida-core apply "$SCRIPT_DIR/patches/0001-frida-core-cloak-support-libartbase.patch" 2>/dev/null; then
  echo "  0001 cloak/libartbase: 已应用"
else
  if grep -q 'libartbase.so' subprojects/frida-core/lib/payload/cloak.vala; then
    echo "  0001 cloak/libartbase: 已存在, 跳过(幂等)"
  else
    echo "  0001 应用失败 —— 请检查 frida-core 版本是否为 ${FRIDA_VERSION}" >&2
    exit 1
  fi
fi

# 补丁2: frida-gum generate-runtime.py 注入桥补丁钩子 + 桥补丁脚本本体
git -C subprojects/frida-gum apply --check "$SCRIPT_DIR/patches/0002-frida-gum-hook-java-bridge-patch.patch" 2>/dev/null || true
if git -C subprojects/frida-gum apply "$SCRIPT_DIR/patches/0002-frida-gum-hook-java-bridge-patch.patch" 2>/dev/null; then
  echo "  0002 gumjs 桥补丁钩子: 已应用"
else
  if grep -q 'wmpdbg-patch-java-bridge.py' subprojects/frida-gum/bindings/gumjs/generate-runtime.py; then
    echo "  0002 gumjs 桥补丁钩子: 已存在, 跳过(幂等)"
  else
    echo "  0002 应用失败 —— 请检查 frida-gum 版本是否为 ${FRIDA_VERSION}" >&2
    exit 1
  fi
fi
cp "$SCRIPT_DIR/patches/wmpdbg-patch-java-bridge.py" \
   subprojects/frida-gum/bindings/gumjs/wmpdbg-patch-java-bridge.py
echo "  桥补丁脚本已就位(bindings/gumjs/)"

echo "===== [3/5] 构建并收集 ====="
CORE_REV="$(git -C subprojects/frida-core rev-parse --short HEAD)"
declare -A SHA256=()
for target in "${TARGETS[@]}"; do
  echo "----- ./configure --host=$target && make -----"
  # releng 的 meson build 目录是 ./build, 按 host 复用 —— 多 target 串行构建时
  # 先清掉上一个 target 的构树(deps/ 工具链会保留, 不用重新下载)
  rm -rf build
  ./configure --host="$target"
  make
  # 产物定位: 实测(releng 20250512)最终 frida-server 生成在
  # build/subprojects/frida-core/server/frida-server(相对 build 根);
  # 路径随 releng 版本可能变, 加全局搜索兜底(精确名匹配, 不会抓到 *-raw)
  bin="build/subprojects/frida-core/server/frida-server"
  if [ ! -f "$bin" ]; then
    bin="$(find build -type f -name 'frida-server' | head -1 || true)"
  fi
  if [ -z "${bin:-}" ] || [ ! -f "$bin" ]; then
    echo "产物不存在: build/**/frida-server ($target)" >&2
    exit 1
  fi
  arch="$(arch_of "$target")"
  out="$DIST/frida-server-${FRIDA_VERSION}-android-${arch}"
  cp "$bin" "$out"
  sha="$(sha256sum "$out" | awk '{print $1}')"
  SHA256[$arch]="$sha"
  echo "  $out  ($sha)"
done

echo "===== [5/5] 生成清单 ====="
(
  cd "$DIST"
  sha256sum frida-server-* | tee SHA256SUMS
)
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SHA_ARGS=()
for target in "${TARGETS[@]}"; do
  arch="$(arch_of "$target")"
  SHA_ARGS+=("${arch}" "${SHA256[$arch]}")
done
python3 - "$DIST/frida-patched-manifest.json" "$FRIDA_VERSION" "$BUILT_AT" "$CORE_REV" "${SHA_ARGS[@]}" <<'PYEOF'
import json, sys
out, version, built_at, core_rev = sys.argv[1:5]
sha = dict(zip(sys.argv[5::2], sys.argv[6::2]))
m = {
    "version": version,
    "note": ("wmpdbg 修复版: cloak/libartbase(修 Android 新ART整机软重启, frida#3365) "
             "+ java-bridge GC 扫描兜底(#387)。协议与官方 " + version +
             " 完全一致, 必须用 SHA256 与官方版区分。"),
    "builtAt": built_at,
    "fridaCoreRev": core_rev,
    "sha256": sha,
}
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(m, f, ensure_ascii=False, indent=2)
    f.write('\n')
PYEOF
cat "$DIST/frida-patched-manifest.json"
echo ""
echo "构建完成。发布: 把 dist/ 下的二进制与 manifest 上传到服务端, 并把"
echo "URL + SHA256 同步进 App 端 fridaServerProvisioner 的修复版清单(或 userData/frida-patched.json 热修)。"
