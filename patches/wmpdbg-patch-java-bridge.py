#!/usr/bin/env python3
"""
wmpdbg-patch-java-bridge.py — 给 npm 安装的 frida-java-bridge 6.3.9 打动态符号补丁(幂等)。

背景:
  Android 15/16 的新 ART(经 Google Play 系统更新推送, 或固件自带)不再导出
  ConcurrentCopying::CopyingPhase 等符号。frida-java-bridge 官方逻辑(6.3.9)在
  api.find() 找不到符号时会【静默跳过 GC 钩子】, 导致 Java hook 在 GC 时崩溃
  (frida-java-bridge#387, 2026-03 oleavr 已确认该失败模式)。

补丁内容(参考 hackcatml 在 frida-java-bridge PR#337 / gist 中验证的思路, 该 PR
未被官方合并):
  1. api.find 找不到 CopyingPhase 且目标为 arm64 时, 用 "CopyingPhase" 字符串引用
     + adrp/add 指令模式扫描定位函数地址, 兜底挂上 GC 钩子。
  2. 扫描代码整体 try/catch 包裹 —— 任何异常都退化为官方行为(不挂), 绝不比官方更糟。

行为约定:
  - 已打过补丁(检测到 wmpdbgLocateCopyingPhaseByScan) → 直接退出 0(幂等)。
  - 锚点不匹配(bridge 版本变了等) → 打印 WARNING 并退出 0, 构建继续(等于没打补丁),
    由构建日志暴露问题, 不硬失败。

用法: python3 wmpdbg-patch-java-bridge.py <path-to-android.js>
由 frida-gum 的 generate-runtime.py 在 npm install 之后自动调用(见 0002 补丁)。
"""
import sys

MARKER = 'wmpdbgLocateCopyingPhaseByScan'

OLD_BLOCK = """  let copyingPhase = null;
  const api = getApi();
  if (apiLevel > 28) {
    copyingPhase = api.find('_ZN3art2gc9collector17ConcurrentCopying12CopyingPhaseEv');
  } else if (apiLevel > 22) {
    copyingPhase = api.find('_ZN3art2gc9collector17ConcurrentCopying12MarkingPhaseEv');
  }
  if (copyingPhase !== null) {
    Interceptor.attach(copyingPhase, artController.hooks.Gc.copyingPhase);
  }
"""

NEW_BLOCK = """  let copyingPhase = null;
  const api = getApi();
  if (apiLevel > 28) {
    copyingPhase = api.find('_ZN3art2gc9collector17ConcurrentCopying12CopyingPhaseEv');
  } else if (apiLevel > 22) {
    copyingPhase = api.find('_ZN3art2gc9collector17ConcurrentCopying12MarkingPhaseEv');
  }
  if (copyingPhase === null && Process.arch === 'arm64') {
    // [wmpdbg] 新 ART(Android 15/16)未导出 CopyingPhase 符号 → 官方逻辑静默跳过 GC
    // 钩子, hook 在 GC 时崩(frida-java-bridge#387)。模式扫描兜底; 任何异常都吞掉,
    // 退化为官方行为(不挂), 不比官方更糟。
    try {
      copyingPhase = wmpdbgLocateCopyingPhaseByScan();
    } catch (e) {
    }
  }
  if (copyingPhase !== null) {
    Interceptor.attach(copyingPhase, artController.hooks.Gc.copyingPhase);
  }
"""

HELPER_ANCHOR = "const artGetOatQuickMethodHeaderInlinedCopyHandler = {"

HELPER = """// [wmpdbg] 定位 art::gc::collector::ConcurrentCopying::CopyingPhase():
// "CopyingPhase" 字符串(该函数内的 CHECK/日志引用) → .text 里 adrp+add 加载该字符串
// 地址的指令 → 从那里向上回溯函数序言(sub sp + stp)。仅 arm64。
// 思路来自 hackcatml(frida-java-bridge PR#337, 未合入官方); 找不到返回 null,
// 由调用方退化为官方行为。
function wmpdbgLocateCopyingPhaseByScan () {
  const sections = Module.enumerateSectionsSync('libart.so');
  const rodata = sections.filter(s => s.name === '.rodata')[0];
  const text = sections.filter(s => s.name === '.text')[0];
  if (rodata === undefined || text === undefined) return null;

  let stringAddr = null;
  for (const match of Memory.scanSync(rodata.address, rodata.size, '43 6f 70 79 69 6e 67 50 68 61 73 65')) {
    stringAddr = match.address;
    break;
  }
  if (stringAddr === null) return null;

  let result = null;
  // arm64: adrp xN, #page ; (可选一条其他指令) ; add xN, xN, #off —— 加载字符串地址的典型序列
  for (const match of Memory.scanSync(text.address, text.size, '?1 ?? FF ?0 21 ?? ?? 91')) {
    let disasm = Instruction.parse(match.address);
    if (disasm.mnemonic !== 'adrp') continue;
    const page = disasm.operands.find(op => op.type === 'imm')?.value;
    if (page === undefined) continue;
    let next = Instruction.parse(disasm.next);
    if (next.mnemonic !== 'add') {
      next = Instruction.parse(next.next);
    }
    if (next.mnemonic !== 'add') continue;
    const offset = next.operands.find(op => op.type === 'imm')?.value;
    if (offset === undefined) continue;
    if (ptr(page).add(offset).toString() !== stringAddr.toString()) continue;

    // 命中引用点, 向上回溯函数序言(sub sp, ... ; stp x29, x30, ...)
    for (let up = 4; up <= 0x4000; up += 4) {
      const d = Instruction.parse(match.address.sub(up));
      if (d.mnemonic === 'sub') {
        const d2 = Instruction.parse(d.next);
        if (d2.mnemonic === 'stp') {
          result = d.address;
          break;
        }
      }
    }
    break;
  }
  return result;
}

"""


def main():
    if len(sys.argv) != 2:
        print('usage: wmpdbg-patch-java-bridge.py <android.js>', file=sys.stderr)
        sys.exit(1)
    path = sys.argv[1]
    src = open(path, encoding='utf-8').read()

    if MARKER in src:
        print(f'[wmpdbg-bridge] {path}: 已打过补丁, 跳过(幂等)')
        return

    if OLD_BLOCK not in src:
        print(f'[wmpdbg-bridge] WARNING: 未找到预期的 6.3.9 代码块, '
              f'frida-java-bridge 版本可能已变 —— 跳过补丁(构建继续, 等价于官方行为)')
        return
    if HELPER_ANCHOR not in src:
        print(f'[wmpdbg-bridge] WARNING: 未找到 helper 插入锚点, 跳过补丁')
        return

    patched = src.replace(OLD_BLOCK, NEW_BLOCK, 1)
    patched = patched.replace(HELPER_ANCHOR, HELPER + HELPER_ANCHOR, 1)
    open(path, 'w', encoding='utf-8', newline='\n').write(patched)
    print(f'[wmpdbg-bridge] {path}: GC 钩子模式扫描兜底补丁已应用')


if __name__ == '__main__':
    main()
