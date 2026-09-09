# 修复版 frida-server 16.7.19（Android）构建包

## 这是什么、为什么需要

官方 frida 16.x 的 `frida-server` 在**新版 ART** 上会触发**整机软重启**：

- 根因（[frida#3365](https://github.com/frida/frida/issues/3365)）：frida-core 的线程数隐藏器（cloak）hook `libart.so` 的 `read`，而 2024-11 起的 ART（Google Play 系统更新推送的 ART 模块，以及 Android 15/16 固件自带版本）把线程统计代码挪到了 `libartbase.so`、且经 FORTIFY 走 `__read_chk` → hook 打空/打错目标 → 软重启。Android 13–16 通杀，与品牌无关。
- 官方 **17.2.13** 才修复，16.x 不再发版；而我们客户端锁 npm `frida@16.7.19`（零依赖脚本依赖 frida 16 运行时内建的全局 `Java`），不能直接升 17。
- 方案 = 从官方 16.7.19 tag 自建补丁版，**协议、版本号与官方完全一致，客户端零改动**。也因此必须靠 **SHA256**（而非版本探测）区分设备上装的是官方版还是修复版 —— App 端已按此实现（`fridaServerProvisioner.js` 的修复版清单 + `adbManager.js` 的哈希校验/强推）。

包含两个补丁：

| # | 目标 | 内容 | 来源 |
|---|------|------|------|
| 0001 | frida-core `lib/payload/cloak.vala` | hook 目标改为优先 `libartbase.so/__read_chk`，逐级回退 `libart.so/read`（老设备）；`__read_chk` 第 4 参 `buflen` 透传，避免 FORTIFY 校验读到脏寄存器 | frida#3365 中 hackcatml / polygraphene 验证的修法 |
| 0002 | frida-gum `generate-runtime.py` + `frida-java-bridge@6.3.9/lib/android.js` | Android 15/16 新 ART 不再导出 `CopyingPhase` 等符号，官方逻辑会**静默跳过 GC 钩子**导致 GC 时崩溃（[frida-java-bridge#387](https://github.com/frida/frida-java-bridge/issues/387)）。补丁加"字符串引用 + adrp/add 模式扫描"兜底；全部 try/catch 包裹，任何异常退化为官方行为，**不比官方更糟** | hackcatml（frida-java-bridge PR#337，未合入官方）思路 |

## 怎么构建（推荐：GitHub Actions，零本地环境）

1. **新建一个私有 GitHub 仓库**，把本目录（`tools/frida-patched/`）的内容作为仓库根目录推上去：
   `build.sh`、`patches/`、`.github/`、`README.md`（`work/`、`dist/` 是构建产物目录，别提交，`.gitignore` 已忽略）。
2. 仓库 **Actions → build-patched-frida-server → Run workflow**。
3. 约 40–90 分钟后，在 run 的 **Artifacts** 下载 `frida-server-patched-android-arm64`：
   - `frida-server-16.7.19-android-arm64`（裸二进制，约 30MB）
   - `SHA256SUMS`
   - `frida-patched-manifest.json`（给 App 端用的版本+哈希清单）

## 怎么构建（本地 Linux / WSL2）

```bash
# Ubuntu 22.04+，依赖同 workflow:
sudo apt-get install -y python3-dev python3-setuptools python3-wheel \
  gperf bison flex gettext pkg-config cmake libtool autoconf automake git
# 可选: export ANDROID_NDK_ROOT=/path/to/ndk (r25b)

bash build.sh                      # android-arm64
bash build.sh android-arm64 android-arm   # 需要 32 位老设备支持时
```

机器要求：4 核 8G 起（8 核 16G 舒服）、磁盘 ≥30G。首次构建 30–90 分钟；改补丁后增量重编约 2–5 分钟。

## 发布流程（产物 → 客户可用）

1. 把 `dist/frida-server-16.7.19-android-<arch>` 与 manifest 上传到**你们自己的服务端**（不要用第三方直链，供应链底线：frida-server 以 root 跑在客户手机上）。
2. 二选一登记进 App：
   - **发版**：更新 `src/main/fridaServerProvisioner.js` 里的 `PATCHED_FRIDA_MANIFEST` 常量（url + sha256）；
   - **热修**：在 App 的 `userData` 目录放 `frida-patched.json`（格式同 manifest + url 字段，见 provisioner 注释），老版本 App 也能用。
3. 客户端行为（已实现）：配置了修复版清单后，一律下发修复版（含老安卓）；设备上已装**官方版**（哈希对不上）会被自动替换；**Android ≥16 且未配置修复版清单时，拒绝启动并提示**（防整机重启）。

## 目录

```
build.sh                        一键构建(本地/CI 通用)
patches/
  0001-frida-core-cloak-support-libartbase.patch     frida-core cloak 修复
  0002-frida-gum-hook-java-bridge-patch.patch        generate-runtime.py 注入钩子
  wmpdbg-patch-java-bridge.py                        桥补丁本体(幂等, 异常降级)
.github/workflows/build.yml     GitHub Actions CI
```

## 升级 frida 基线版本时

改 `build.sh` 的 `FRIDA_VERSION`。注意：0001/0002 是对 16.7.19 精确打的补丁，版本变了要重新校准上下文（`git apply` 失败会明确报错，不会静默打错）；若升到 ≥17.2.13，cloak 修复官方已含，0001 可去掉，但 17 的运行时没有内建全局 `Java`，注入脚本体系要跟着换 —— 见主仓库讨论（方案③）。
