#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SIG:BEGIN:header
# ============================================================
#  署名信息 / ATTRIBUTION  —  请勿删除 (DO NOT REMOVE)
#  制作人：徐徐
#  微信：doublebean_vip
#  Copyright (c) 2026 徐徐. All Rights Reserved.
# ============================================================
# SIG:END:header
"""
署名注入 / 校验工具 (Signature Guard) —— 低调版

制作人：徐徐   微信：doublebean_vip

设计要点
--------
1. 每一处署名都是一个「带哨兵标记的规范块」：

       <!-- SIG:BEGIN:footer -->
       ...规范内容...
       <!-- SIG:END:footer -->

   校验是**逐组件、逐字**的：删掉任何一处、或把「徐徐」改成别的字、
   或只删块里一行，都会被检出（tampered / missing）。

2. 视觉低调：页脚是一行 11px 浅灰小字 + 54px 半透明灰度二维码，
   悬停时二维码才稍微变清楚。不做大横幅、不用醒目颜色。

3. 二维码数据外置在 tools/qr_data.txt（base64 单行），并以 sha256 钉死；
   assets/wechat_qr.png 必须与 qr_data.txt 内容一致。
   二维码源被偷换 -> check 直接 FAIL。

4. 修复（inject）=「剥离旧块 + 重插规范块」，字节级还原、天然幂等。

用法
----
    python tools/signature_guard.py inject   # 注入/修复所有署名（幂等）
    python tools/signature_guard.py check    # 校验；不完整则退出码 1（CI 用）
    python tools/signature_guard.py list     # 列出受保护组件清单
"""

import base64
import hashlib
import io
import json
import os
import re
import sys

# ================================================================ 署名常量
AUTHOR_NAME = "徐徐"
AUTHOR_WECHAT = "doublebean_vip"
COPYRIGHT = "Copyright (c) 2026 徐徐. All Rights Reserved."
MARKER = "制作人：徐徐"

# tools/qr_data.txt（微信二维码 base64）的 sha256，钉死二维码源
QR_HASH = "1adc2cc0fe3713656e885374fd3f4dc2579d434cd79527389bee2f0fe7759ef6"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ================================================================ 基础 IO
def rel(path):
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def read(path):
    """utf-8-sig 自动剥离 BOM，避免 PowerShell 写入的 BOM 污染文件。"""
    with io.open(path, "r", encoding="utf-8-sig") as f:
        return f.read()


def write(path, text):
    """统一写 UTF-8 无 BOM（与仓库原有编码一致）。"""
    with io.open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def exists(rp):
    return os.path.isfile(os.path.join(ROOT, rp))


def load_qr_b64():
    """读取并校验二维码 base64；哈希不符或缺失返回 None。"""
    p = os.path.join(ROOT, "tools", "qr_data.txt")
    if not os.path.isfile(p):
        return None
    s = read(p).strip()
    if sha256_bytes(s.encode("utf-8")) != QR_HASH:
        return None
    return s


QR_B64 = load_qr_b64() or ""
QR_URI = ("data:image/png;base64," + QR_B64) if QR_B64 else ""


# ================================================================ 哨兵块机制
COMMENT = {
    "html": ("<!-- SIG:BEGIN:%s -->", "<!-- SIG:END:%s -->"),
    "css": ("/* SIG:BEGIN:%s */", "/* SIG:END:%s */"),
    "js": ("/* SIG:BEGIN:%s */", "/* SIG:END:%s */"),
    "py": ("# SIG:BEGIN:%s", "# SIG:END:%s"),
    "yml": ("# SIG:BEGIN:%s", "# SIG:END:%s"),
}


def block_regex(kind, name):
    b, e = COMMENT[kind]
    return re.compile(re.escape(b % name) + r"\n(.*?)\n" + re.escape(e % name), re.DOTALL)


def make_block(kind, name, body):
    b, e = COMMENT[kind]
    return (b % name) + "\n" + body + "\n" + (e % name)


def find_block(s, kind, name):
    return block_regex(kind, name).search(s)


def upsert_block(s, kind, name, body, anchor=None, before=False):
    """插入或修复一个哨兵块。

    返回 (新文本, 动作)；动作 ∈ {'', 'inserted', 'repaired', 'ANCHOR-NOT-FOUND'}。
    """
    full = make_block(kind, name, body)
    m = find_block(s, kind, name)
    if m:
        if m.group(0) == full:
            return s, ""
        return s[: m.start()] + full + s[m.end():], "repaired"

    if anchor is None or anchor not in s:
        return s, "ANCHOR-NOT-FOUND"
    i = s.find(anchor)
    if before:
        head = s[:i].rstrip("\n")
        if head:
            head += "\n"
        return head + full + "\n" + s[i:], "inserted"
    j = i + len(anchor)
    tail = "\n" + s[j:].lstrip("\n")
    return s[:j] + "\n" + full + tail, "inserted"


def check_block(s, kind, name, body):
    full = make_block(kind, name, body)
    m = find_block(s, kind, name)
    if not m:
        return "missing"
    return "ok" if m.group(0) == full else "tampered"


def squeeze_blanks(lines, idx, keep=0):
    """压缩 lines[idx] 起连续的空白行，使插入形态收敛（幂等 + 字节级还原）。"""
    n = 0
    while idx + n < len(lines) and lines[idx + n].strip() == "":
        n += 1
    if n > keep:
        del lines[idx + keep: idx + n]
    return lines


# ================================================================ 规范内容
# 低调版：只留一行小注释 + 两个 meta
HTML_META_BODY = """    <!-- 署名（请勿删除 / DO NOT REMOVE）| 制作人：徐徐 | 微信：doublebean_vip -->
    <meta name="author" content="徐徐">
    <meta name="copyright" content="Copyright (c) 2026 徐徐. All Rights Reserved.">"""

# 低调版：浅灰小字、二维码小且半透明灰度，悬停才稍微变清楚
HTML_CSS_BODY = """        /* ===== 署名样式（请勿删除 / DO NOT REMOVE） ===== */
        .site-footer {
            margin-top: 22px;
            padding-top: 10px;
            border-top: 1px solid #f0f0f0;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 6px;
            color: #c4c4c4;
            font-size: 11px;
            line-height: 1.6;
            opacity: .8;
        }

        .site-footer .sig-sep {
            color: #ddd;
        }

        .site-footer .sig-qr {
            width: 54px;
            height: 54px;
            margin-left: 4px;
            opacity: .45;
            filter: grayscale(1);
            transition: opacity .25s ease;
        }

        .site-footer:hover .sig-qr {
            opacity: .85;
        }"""

def footer_body():
    """惰性构造：二维码 URI 可能在运行中被 recover_qr 恢复后改变。"""
    return (
        "        <!-- 署名（请勿删除 / DO NOT REMOVE）| 制作人：徐徐 | 微信：doublebean_vip -->\n"
        '        <footer class="site-footer" id="siteFooter">\n'
        '            <span class="sig-line">制作人：徐徐、任欣</span>\n'
        '            <span class="sig-sep">·</span>\n'
        '            <span class="sig-line">微信：doublebean_vip</span>\n'
        '            <img class="sig-qr" alt="微信二维码" title="微信：doublebean_vip"\n'
        '                 src="' + QR_URI + '">\n'
        "        </footer>"
    )

def guard_body():
    """惰性构造：同 footer_body。"""
    return (
    "        /* ============================================================\n"
    "         *  署名保护 / SIGNATURE GUARD  —  请勿删除 (DO NOT REMOVE)\n"
    "         *  制作人：徐徐\n"
    "         *  微信：doublebean_vip\n"
    "         *  Copyright (c) 2026 徐徐. All Rights Reserved.\n"
    "         *\n"
    "         *  作用：即使有人从 HTML 里删掉页脚署名，本段代码也会在运行时\n"
    "         *  自动把它重建回来，并在控制台告警。\n"
    "         * ============================================================ */\n"
    "        const AUTHOR_SIGNATURE = Object.freeze({\n"
    "            name: '徐徐、任欣',\n"
    "            wechat: 'doublebean_vip',\n"
    "            qr: '" + QR_URI + "',\n"
    "            copyright: 'Copyright © 2026 徐徐. All Rights Reserved.'\n"
    "        });\n"
    "\n"
    "        (function signatureGuard() {\n"
    "            const FOOTER_ID = 'siteFooter';\n"
    "            const WARN = '[署名保护] 检测到署名被移除，已自动恢复。' +\n"
    "                         '制作人：徐徐、任欣（微信：doublebean_vip）';\n"
    "\n"
    "            function buildFooter() {\n"
    "                const f = document.createElement('footer');\n"
    "                f.className = 'site-footer';\n"
    "                f.id = FOOTER_ID;\n"
    "                f.innerHTML =\n"
    "                    '<span class=\"sig-line\">制作人：' + AUTHOR_SIGNATURE.name + '</span>' +\n"
    "                    '<span class=\"sig-sep\">·</span>' +\n"
    "                    '<span class=\"sig-line\">微信：' + AUTHOR_SIGNATURE.wechat + '</span>' +\n"
    "                    '<img class=\"sig-qr\" alt=\"微信二维码\" title=\"微信：' + AUTHOR_SIGNATURE.wechat +\n"
    "                    '\" src=\"' + AUTHOR_SIGNATURE.qr + '\">';\n"
    "                return f;\n"
    "            }\n"
    "\n"
    "            function ensure() {\n"
    "                if (document.getElementById(FOOTER_ID)) return;\n"
    "                const host = document.querySelector('.container') || document.body;\n"
    "                if (!host) return;\n"
    "                host.appendChild(buildFooter());\n"
    "                try { console.warn('%c' + WARN, 'color:#c0392b;font-weight:bold;'); } catch (e) {}\n"
    "            }\n"
    "\n"
    "            if (document.readyState === 'loading') {\n"
    "                document.addEventListener('DOMContentLoaded', ensure);\n"
    "            } else {\n"
    "                ensure();\n"
    "            }\n"
    "\n"
    "            // 监听 DOM 变化：署名节点被删除时立即恢复\n"
    "            try {\n"
    "                new MutationObserver(function () { ensure(); })\n"
    "                    .observe(document.documentElement, { childList: true, subtree: true });\n"
    "            } catch (e) { /* 极老浏览器忽略 */ }\n"
    "\n"
    "            // 控制台常驻署名（低调）\n"
    "            try {\n"
    "                console.log(\"%c中铁十八局集团市政工程有限公司'桂水安'题库系统%c  制作人：徐徐、任欣 · 微信：doublebean_vip\",\n"
    "                    'background:#bbb;color:#fff;padding:1px 6px;border-radius:3px;',\n"
    "                    'color:#999;');\n"
    "                console.log('%c' + AUTHOR_SIGNATURE.copyright, 'color:#ccc;');\n"
    "            } catch (e) {}\n"
    "        })();"
    )

# 数据加载时剥离下划线开头的元数据键，避免 _signature 出现在分类按钮里
HTML_STRIP_BODY = """        // 剥离下划线开头的署名/元数据键，避免其出现在分类列表中
        // （署名信息本身仍完整保留在文件里）
        function stripSignatureMeta(data) {
            const out = {};
            Object.keys(data || {}).forEach(function (k) {
                if (!k.startsWith('_')) out[k] = data[k];
            });
            return out;
        }"""

# 注意：body 自身必须是完整的 JS 注释（哨兵标记也是注释），
# 否则 questions-data.js 会语法错误。
JS_HEADER_BODY = """/* ============================================================
 *  题库数据 / Quiz Data
 *  署名信息 / ATTRIBUTION  —  请勿删除 (DO NOT REMOVE)
 *  制作人：徐徐
 *  微信：doublebean_vip
 *  Copyright (c) 2026 徐徐. All Rights Reserved.
 * ============================================================ */"""

JS_TAIL_BODY = """try {
    window.QUIZ_DATA._signature = Object.freeze({
        author: '徐徐',
        wechat: 'doublebean_vip',
        copyright: 'Copyright (c) 2026 徐徐. All Rights Reserved.',
        notice: '制作人：徐徐 — 请勿删除本署名信息 / DO NOT REMOVE THIS ATTRIBUTION'
    });
} catch (e) {}"""

JSON_SIG = {
    "author": AUTHOR_NAME,
    "wechat": AUTHOR_WECHAT,
    "copyright": COPYRIGHT,
    "notice": "制作人：徐徐 — 请勿删除本署名信息 / DO NOT REMOVE THIS ATTRIBUTION",
}

PY_HEADER_BODY = """# ============================================================
#  署名信息 / ATTRIBUTION  —  请勿删除 (DO NOT REMOVE)
#  制作人：徐徐
#  微信：doublebean_vip
#  Copyright (c) 2026 徐徐. All Rights Reserved.
# ============================================================"""

# 注意：「制作人：徐徐」必须是连续纯文本（不能加粗体标记），
# 否则 MARKER 精确匹配不上。
MD_HEADER_BODY = """> **署名 / Attribution**
> 制作人：徐徐 　微信：doublebean_vip
> Copyright (c) 2026 徐徐. All Rights Reserved. — 请勿删除本署名信息。"""

YML_HEADER_BODY = """# ============================================================
#  署名信息 / ATTRIBUTION  —  请勿删除 (DO NOT REMOVE)
#  制作人：徐徐
#  微信：doublebean_vip
#  Copyright (c) 2026 徐徐. All Rights Reserved.
# ============================================================"""

# pages.yml 里「部署前强制校验署名」的步骤（哨兵块包裹，可整块替换不重复插入）
YML_GUARD_BODY = """      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      # 署名校验：缺失或被篡改则部署中止（制作人：徐徐 / 微信 doublebean_vip）
      - name: Verify author signature (blocks deploy if removed)
        run: python tools/signature_guard.py check"""

# 页脚插入锚点：容忍块被删除后残留的任意空行
FOOT_ANCHOR_RE = re.compile(
    r'(            <button class="btn-restart" onclick="restart\(\)">重新开始</button>\n'
    r'        </div>\n)'
    r'(?:[ \t]*\n)*'
    r'(    </div>)'
)

# stripSignatureMeta 的两种接线（被断开后用于自愈）
STRIP_WIRE_OLD_JS = """            if (window.QUIZ_DATA && Object.keys(window.QUIZ_DATA).length > 0) {
                quizData = window.QUIZ_DATA;"""
STRIP_WIRE_NEW_JS = """            if (window.QUIZ_DATA && Object.keys(window.QUIZ_DATA).length > 0) {
                quizData = stripSignatureMeta(window.QUIZ_DATA);"""
STRIP_WIRE_OLD_FETCH = """                const response = await fetch('questions.json');
                quizData = await response.json();"""
STRIP_WIRE_NEW_FETCH = """                const response = await fetch('questions.json');
                quizData = stripSignatureMeta(await response.json());"""

LICENSE_TEXT = """Copyright (c) 2026 徐徐（微信：doublebean_vip）

保留所有权利 / All Rights Reserved.

--------------------------------------------------------------------
署名与使用许可 (Attribution & Terms of Use)
--------------------------------------------------------------------

1. 本仓库（含题库系统网页、题库数据、转换脚本、文档等全部内容）的
   作者与著作权人为 **徐徐**（微信: doublebean_vip）。

2. 任何复制、分发、展示或二次使用本仓库内容的行为，**必须**在所有
   副本中完整保留本文件、`AUTHORS.md`、`SIGNATURE.json` 以及各源文件
   中的署名信息（"制作人：徐徐 / 微信：doublebean_vip"）。

3. **禁止删除、隐藏、替换或伪造署名信息**，包括但不限于：
   - 删除或注释掉源文件中的署名头部；
   - 移除网页页脚署名、微信二维码或 `AUTHOR_SIGNATURE` 运行时常量；
   - 移除 `<meta name="author">` 等元数据标签；
   - 删除 `_signature` 数据字段；
   - 替换 `tools/qr_data.txt` 中的二维码（其 sha256 已被校验钉死）；
   - 通过压缩、混淆、改名等手段使署名不可见。

4. 未经作者书面许可，**不得**将本仓库内容用于商业用途，亦不得
   声称自己为本作品的作者。

5. 本作品按"原样"提供，作者不作任何明示或暗示的担保。

--------------------------------------------------------------------
技术保护措施 / Technical Enforcement
--------------------------------------------------------------------

本仓库配置了自动署名校验：
  - `tools/signature_guard.py check` 会在每次 push / pull_request 时由
    GitHub Actions 执行；
  - 署名缺失或被篡改将导致 CI 失败，并使 GitHub Pages **停止部署**；
  - 校验采用「哨兵块逐字比对」：每处署名都被 SIG:BEGIN / SIG:END 标记
    包裹，删除其中任何一行、或把作者名改成别的字，都会被检出。

--------------------------------------------------------------------
联系方式 / Contact
--------------------------------------------------------------------
制作人：徐徐
微信：doublebean_vip
"""

AUTHORS_TEXT = """# 署名 / AUTHORS

| 角色 | 姓名 | 微信 |
| ---- | ---- | ---- |
| 制作人 (Author) | **徐徐** | doublebean_vip |

**Copyright (c) 2026 徐徐. All Rights Reserved.**

---

## 声明

本项目（题库系统）由 **徐徐** 独立制作，包括网页界面、题库数据结构、
格式转换脚本与全部文档。

任何人在复制、分发或二次使用本项目内容时，**必须完整保留本文件及所有
源文件中的署名信息**，不得删除、隐藏、替换或伪造。

详细条款见 [`LICENSE`](./LICENSE)。

## 署名保护机制

本项目所有署名都是「带哨兵标记的规范块」，由 `tools/signature_guard.py`
统一维护，共 5 层保护：

| 层级 | 位置 | 作用 |
| ---- | ---- | ---- |
| 1 | `index.html` `<meta name="author">` | 浏览器 / 搜索引擎可见的作者元数据 |
| 2 | `index.html` 页脚（含微信二维码） | 打开页面可见的低调署名 |
| 3 | `index.html` `AUTHOR_SIGNATURE` + MutationObserver | 运行时自愈：页脚被删会自动重建并告警 |
| 4 | `questions-data.js` / `questions.json` 的 `_signature` | 数据文件自带署名，脱离网页也能溯源 |
| 5 | GitHub Actions（两个工作流） | 署名被删/被改则 CI 失败，Pages 停止部署 |

微信二维码以 base64 存于 `tools/qr_data.txt`，其 sha256 被校验脚本钉死；
`assets/wechat_qr.png` 为同一图片的本地留档。

校验命令：

```bash
python tools/signature_guard.py check    # 校验，不完整则退出码 1
python tools/signature_guard.py inject   # 注入 / 修复（幂等，字节级还原）
python tools/signature_guard.py list     # 列出全部受保护组件
```

---

制作人：徐徐 　微信：doublebean_vip
"""

GUARD_WORKFLOW = """# ============================================================
#  署名信息 / ATTRIBUTION  —  请勿删除 (DO NOT REMOVE)
#  制作人：徐徐
#  微信：doublebean_vip
#  Copyright (c) 2026 徐徐. All Rights Reserved.
#
#  作用：每次 push / PR 逐字校验全部署名块，缺失或被篡改即失败。
# ============================================================
name: Signature Guard

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  signature-check:
    name: Verify author signature
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Check signature integrity (fails if removed or tampered)
        run: python tools/signature_guard.py check
"""


# ================================================================ 文件枚举
def py_files():
    out = [os.path.join(ROOT, n) for n in sorted(os.listdir(ROOT))
           if n.endswith(".py") and os.path.isfile(os.path.join(ROOT, n))]
    out.append(os.path.join(ROOT, "tools", "signature_guard.py"))
    return [p for p in out if os.path.isfile(p)]


def md_files():
    return [os.path.join(ROOT, n) for n in sorted(os.listdir(ROOT))
            if n.endswith(".md") and os.path.isfile(os.path.join(ROOT, n))
            and n != "AUTHORS.md"]


def protected_files():
    out = ["index.html", "questions-data.js", "questions.json", "LICENSE",
           "AUTHORS.md", "SIGNATURE.json", "tools/qr_data.txt", "assets/wechat_qr.png",
           ".github/workflows/pages.yml", ".github/workflows/signature-guard.yml",
           "tools/signature_guard.py"]
    out += [rel(p) for p in py_files()]
    out += [rel(p) for p in md_files()]
    seen, res = set(), []
    for rp in out:
        if rp not in seen and exists(rp):
            seen.add(rp)
            res.append(rp)
    return res


# ================================================================ 注入
# 用户已要求删除旧 email；若有人把它加回任何受保护文件，inject 清除该行
STALE_EMAIL = "doublebean@vip.qq.com"
STALE_SKIP = ("tools/signature_guard.py", "SIGNATURE.json", "tools/qr_data.txt",
              "assets/wechat_qr.png")


def inject_stale_email(log):
    acts = []
    for rp in protected_files():
        if rp in STALE_SKIP:
            continue
        if not rp.endswith((".html", ".js", ".py", ".md", ".yml")):
            continue
        p = os.path.join(ROOT, rp)
        s = read(p)
        if STALE_EMAIL not in s:
            continue
        lines = [l for l in s.split("\n") if STALE_EMAIL not in l]
        text = "\n".join(lines)
        # 收敛删除后残留的末尾多余空行，保证可字节级还原
        if text.endswith("\n\n"):
            text = text.rstrip("\n") + "\n"
        write(p, text)
        acts.append(rp)
    return acts


def recover_qr(log):
    """qr_data.txt 被偷换/删除时，从 assets/wechat_qr.png 交叉恢复。

    两者互为冗余：只要还有一个是好的（哈希匹配 QR_HASH），另一个就能还原。
    两个都被换则无法自动恢复，需 git checkout（CI 已阻断部署）。
    """
    global QR_B64, QR_URI
    if load_qr_b64():
        return []
    prp = os.path.join(ROOT, "assets", "wechat_qr.png")
    if os.path.isfile(prp):
        png_b64 = base64.b64encode(open(prp, "rb").read()).decode("ascii")
        if sha256_bytes(png_b64.encode("utf-8")) == QR_HASH:
            write(os.path.join(ROOT, "tools", "qr_data.txt"), png_b64 + "\n")
            QR_B64 = png_b64
            QR_URI = "data:image/png;base64," + QR_B64
            return ["qr_data:recovered-from-png"]
    return ["qr_data:UNRECOVERABLE(use git checkout)"]


def inject_html(log):
    p = os.path.join(ROOT, "index.html")
    if not os.path.isfile(p):
        log.append("  index.html 不存在，跳过")
        return []
    if not QR_B64:
        log.append("  !! tools/qr_data.txt 缺失或哈希不符，跳过 HTML 注入")
        return ["qr-missing"]
    s = read(p)
    orig = s
    acts = []

    # 1) head 元数据
    s, a = upsert_block(
        s, "html", "meta", HTML_META_BODY,
        anchor='<meta name="viewport" content="width=device-width, initial-scale=1.0">',
    )
    if a:
        acts.append("meta:" + a)

    # 2) 页脚样式
    s, a = upsert_block(s, "css", "css", HTML_CSS_BODY, anchor="    </style>", before=True)
    if a:
        acts.append("css:" + a)

    # 3) 页脚 DOM
    fm = find_block(s, "html", "footer")
    foot_full = make_block("html", "footer", footer_body())
    if fm:
        if fm.group(0) != foot_full:
            s = s[: fm.start()] + foot_full + s[fm.end():]
            acts.append("footer:repaired")
    else:
        m = FOOT_ANCHOR_RE.search(s)
        if m:
            s = s[: m.start()] + m.group(1) + "\n" + foot_full + "\n" + m.group(2) + s[m.end():]
            acts.append("footer:inserted")
        else:
            acts.append("footer:ANCHOR-NOT-FOUND")

    # 4) 运行时保护脚本
    s, a = upsert_block(s, "js", "guard", guard_body(),
                        anchor="    </script>\n</body>", before=True)
    if a:
        acts.append("guard:" + a)

    # 5) stripSignatureMeta 块
    strip_full = make_block("js", "strip", HTML_STRIP_BODY)
    sm = find_block(s, "js", "strip")
    if sm:
        if sm.group(0) != strip_full:
            s = s[: sm.start()] + strip_full + s[sm.end():]
            acts.append("strip:repaired")
    else:
        old_load = """        async function loadQuizData() {
            if (window.QUIZ_DATA && Object.keys(window.QUIZ_DATA).length > 0) {
                quizData = window.QUIZ_DATA;
                init();
                return;
            }
            try {
                const response = await fetch('questions.json');
                quizData = await response.json();
                init();"""
        new_load = strip_full + """

        async function loadQuizData() {
            if (window.QUIZ_DATA && Object.keys(window.QUIZ_DATA).length > 0) {
                quizData = stripSignatureMeta(window.QUIZ_DATA);
                init();
                return;
            }
            try {
                const response = await fetch('questions.json');
                quizData = stripSignatureMeta(await response.json());
                init();"""
        if old_load in s:
            s = s.replace(old_load, new_load, 1)
            acts.append("strip:inserted")
        elif "stripSignatureMeta" in s:
            acts.append("strip:present-unwrapped")
        else:
            acts.append("strip:ANCHOR-NOT-FOUND")

    # 6) 接线自愈
    if STRIP_WIRE_OLD_JS in s:
        s = s.replace(STRIP_WIRE_OLD_JS, STRIP_WIRE_NEW_JS, 1)
        acts.append("wire-js:repaired")
    if STRIP_WIRE_OLD_FETCH in s:
        s = s.replace(STRIP_WIRE_OLD_FETCH, STRIP_WIRE_NEW_FETCH, 1)
        acts.append("wire-fetch:repaired")

    if s != orig:
        write(p, s)
    return acts


def inject_js_data(log):
    p = os.path.join(ROOT, "questions-data.js")
    if not os.path.isfile(p):
        return []
    s = read(p)
    orig = s
    acts = []

    head_full = make_block("js", "header", JS_HEADER_BODY)
    hm = find_block(s, "js", "header")
    if hm:
        if hm.group(0) != head_full:
            s = s[: hm.start()] + head_full + s[hm.end():]
            acts.append("header:repaired")
    else:
        s = head_full + "\n" + s.lstrip("\n")
        acts.append("header:inserted")

    tail_full = make_block("js", "sig", JS_TAIL_BODY)
    tm = find_block(s, "js", "sig")
    if tm:
        if tm.group(0) != tail_full:
            s = s[: tm.start()] + tail_full + s[tm.end():]
            acts.append("sig:repaired")
    else:
        s = re.sub(r"\n/\* ===== 署名元数据.*?\n\} catch \(e\) \{\}\n?", "", s, flags=re.DOTALL)
        s = s.rstrip("\n") + "\n\n" + tail_full + "\n"
        acts.append("sig:inserted")

    if s != orig:
        write(p, s)
    return acts


def inject_json_data(log):
    p = os.path.join(ROOT, "questions.json")
    if not os.path.isfile(p):
        return []
    raw = read(p)
    try:
        d = json.loads(raw)
    except Exception as e:
        log.append("  questions.json 解析失败：%s" % e)
        return ["parse-error"]

    if d.get("_signature") == JSON_SIG:
        return []

    had = "_signature" in d
    new = {"_signature": JSON_SIG}
    for k, v in d.items():
        if not k.startswith("_"):
            new[k] = v
    write(p, json.dumps(new, ensure_ascii=False, indent=2) + "\n")
    json.loads(read(p))
    return ["sig:repaired" if had else "sig:inserted"]


def inject_py(log):
    out = {}
    for p in py_files():
        raw = read(p)
        s, a = upsert_block(raw, "py", "header", PY_HEADER_BODY)
        if a == "ANCHOR-NOT-FOUND":
            s = re.sub(
                r"^# =+\n#  署名信息 / ATTRIBUTION.*?\n# =+\n",
                "", s, flags=re.DOTALL | re.MULTILINE)
            lines = s.split("\n")
            idx = 0
            while idx < len(lines) and (lines[idx].startswith("#!") or "coding" in lines[idx]):
                idx += 1
            squeeze_blanks(lines, idx, keep=0)
            lines.insert(idx, make_block("py", "header", PY_HEADER_BODY))
            s = "\n".join(lines)
            a = "inserted"
        if s != raw:
            write(p, s)
            out[rel(p)] = [a]
    return out


def inject_md(log):
    out = {}
    for p in md_files():
        raw = read(p)
        s, a = upsert_block(raw, "html", "mdheader", MD_HEADER_BODY)
        if a == "ANCHOR-NOT-FOUND":
            s = re.sub(r"^> \*\*署名 / Attribution\*\*\n(?:> .*\n|\n)*?\n?", "", s)
            lines = s.split("\n")
            block = make_block("html", "mdheader", MD_HEADER_BODY)
            if lines and lines[0].startswith("# "):
                squeeze_blanks(lines, 1, keep=0)
                lines.insert(1, "\n" + block + "\n")
            else:
                squeeze_blanks(lines, 0, keep=0)
                lines.insert(0, block + "\n")
            s = "\n".join(lines)
            a = "inserted"
        if s != raw:
            write(p, s)
            out[rel(p)] = [a]
    return out


def inject_yml(log):
    out = {}
    p = os.path.join(ROOT, ".github", "workflows", "pages.yml")
    if os.path.isfile(p):
        raw = read(p)
        acts = []
        s, a = upsert_block(raw, "yml", "header", YML_HEADER_BODY)
        if a == "ANCHOR-NOT-FOUND":
            s = re.sub(r"^# =+\n#  署名信息 / ATTRIBUTION.*?\n# =+\n", "", s,
                       flags=re.DOTALL | re.MULTILINE)
            lines = s.split("\n")
            squeeze_blanks(lines, 0, keep=0)
            s = make_block("yml", "header", YML_HEADER_BODY) + "\n" + "\n".join(lines)
            a = "inserted"
        if a:
            acts.append("header:" + a)

        anchor = "      - name: Checkout\n        uses: actions/checkout@v4\n"
        s, a2 = upsert_block(s, "yml", "deploy-guard", YML_GUARD_BODY, anchor=anchor)
        if a2:
            acts.append("deploy-guard:" + a2)

        if s != raw:
            write(p, s)
        if acts:
            out[rel(p)] = acts
    return out


def create_static_files(log):
    created = []
    for rp, text in (("LICENSE", LICENSE_TEXT),
                     ("AUTHORS.md", AUTHORS_TEXT),
                     (".github/workflows/signature-guard.yml", GUARD_WORKFLOW)):
        p = os.path.join(ROOT, rp)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if not os.path.isfile(p) or read(p) != text:
            write(p, text)
            created.append(rp)
    return created


def inject_assets(log):
    """assets/wechat_qr.png 可由 tools/qr_data.txt 还原（本地留档自愈）。

    qr_data.txt 本身是唯一不可自动还原的源（受 git 保护）。
    """
    acts = []
    if not QR_B64:
        return acts
    prp = os.path.join(ROOT, "assets", "wechat_qr.png")
    os.makedirs(os.path.dirname(prp), exist_ok=True)
    want = base64.b64decode(QR_B64)
    cur = open(prp, "rb").read() if os.path.isfile(prp) else None
    if cur != want:
        with open(prp, "wb") as f:
            f.write(want)
        acts.append("wechat_qr.png:repaired" if cur else "wechat_qr.png:inserted")
    return acts


def write_manifest(log):
    files = {}
    for rp in protected_files():
        if rp == "SIGNATURE.json":
            continue
        p = os.path.join(ROOT, rp)
        if os.path.isfile(p):
            files[rp] = sha256(p)
    manifest = {
        "_comment": "请勿删除本文件。署名清单与文件指纹，由 tools/signature_guard.py 维护。",
        "author": AUTHOR_NAME,
        "wechat": AUTHOR_WECHAT,
        "attribution": "制作人：徐徐（微信：doublebean_vip）",
        "copyright": COPYRIGHT,
        "notice": "禁止删除、隐藏、替换或伪造署名信息。详见 LICENSE。",
        "marker": MARKER,
        "qr_sha256": QR_HASH,
        "protected_files": sorted(files.keys()),
        "sha256": files,
    }
    write(os.path.join(ROOT, "SIGNATURE.json"),
          json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return manifest


# ================================================================ 校验
def collect_components():
    """返回 [(组件名, 文件, 状态, 说明)]，状态 ∈ ok/tampered/missing。"""
    res = []

    hp = os.path.join(ROOT, "index.html")
    if os.path.isfile(hp):
        s = read(hp)
        for name, kind, body in (("meta", "html", HTML_META_BODY),
                                 ("css", "css", HTML_CSS_BODY),
                                 ("footer", "html", footer_body()),
                                 ("guard", "js", guard_body()),
                                 ("strip", "js", HTML_STRIP_BODY)):
            res.append(("index.html:%s" % name, "index.html",
                        check_block(s, kind, name, body), ""))
        used = s.count("stripSignatureMeta(")
        res.append(("index.html:strip-wired", "index.html",
                    "ok" if used >= 3 else "tampered",
                    "stripSignatureMeta 调用次数=%d（期望>=3）" % used))
    else:
        res.append(("index.html", "index.html", "missing", "文件不存在"))

    jp = os.path.join(ROOT, "questions-data.js")
    if os.path.isfile(jp):
        s = read(jp)
        res.append(("questions-data.js:header", "questions-data.js",
                    check_block(s, "js", "header", JS_HEADER_BODY), ""))
        res.append(("questions-data.js:sig", "questions-data.js",
                    check_block(s, "js", "sig", JS_TAIL_BODY), ""))
        res.append(("questions-data.js:data-intact", "questions-data.js",
                    "ok" if "window.QUIZ_DATA = {" in s else "tampered", "数据主体"))
    else:
        res.append(("questions-data.js", "questions-data.js", "missing", "文件不存在"))

    qp = os.path.join(ROOT, "questions.json")
    if os.path.isfile(qp):
        try:
            d = json.loads(read(qp))
            sig = d.get("_signature")
            if sig == JSON_SIG:
                st, note = "ok", ""
            elif sig is None:
                st, note = "missing", "缺 _signature 字段"
            else:
                diff = [k for k in JSON_SIG if sig.get(k) != JSON_SIG[k]]
                st, note = "tampered", "_signature 字段被改：%s" % diff
            res.append(("questions.json:_signature", "questions.json", st, note))
        except Exception as e:
            res.append(("questions.json:_signature", "questions.json", "tampered",
                        "JSON 解析失败：%s" % e))
    else:
        res.append(("questions.json", "questions.json", "missing", "文件不存在"))

    for rp, text in (("LICENSE", LICENSE_TEXT),
                     ("AUTHORS.md", AUTHORS_TEXT),
                     (".github/workflows/signature-guard.yml", GUARD_WORKFLOW)):
        if not exists(rp):
            res.append((rp, rp, "missing", "文件不存在"))
        else:
            s = read(rp)
            res.append((rp, rp, "ok" if s == text else "tampered",
                        "" if s == text else "内容与规范版不符"))

    wp = os.path.join(ROOT, ".github", "workflows", "pages.yml")
    if os.path.isfile(wp):
        s = read(wp)
        res.append(("pages.yml:header", ".github/workflows/pages.yml",
                    check_block(s, "yml", "header", YML_HEADER_BODY), ""))
        gst = check_block(s, "yml", "deploy-guard", YML_GUARD_BODY)
        res.append(("pages.yml:deploy-guard", ".github/workflows/pages.yml", gst,
                    "" if gst == "ok" else "部署前校验步骤缺失或被篡改"))
        if "signature_guard.py check" in s and "Deploy to GitHub Pages" in s:
            ok_order = s.index("signature_guard.py check") < s.index("Deploy to GitHub Pages")
            res.append(("pages.yml:guard-order", ".github/workflows/pages.yml",
                        "ok" if ok_order else "tampered",
                        "" if ok_order else "校验步骤被移到部署之后"))
    else:
        res.append(("pages.yml", ".github/workflows/pages.yml", "missing", "文件不存在"))

    for p in py_files():
        rp = rel(p)
        res.append(("%s:header" % rp, rp,
                    check_block(read(p), "py", "header", PY_HEADER_BODY), ""))

    for p in md_files():
        rp = rel(p)
        res.append(("%s:header" % rp, rp,
                    check_block(read(p), "html", "mdheader", MD_HEADER_BODY), ""))

    # 二维码源：哈希钉死
    qrp = "tools/qr_data.txt"
    if exists(qrp):
        s = read(qrp).strip()
        ok = sha256_bytes(s.encode("utf-8")) == QR_HASH
        res.append((qrp, qrp, "ok" if ok else "tampered",
                    "" if ok else "二维码 base64 哈希不符（源被偷换？）"))
        # 本地留档 png 必须与 qr_data 一致
        prp = "assets/wechat_qr.png"
        if exists(prp):
            png_b64 = base64.b64encode(open(os.path.join(ROOT, prp), "rb").read()).decode("ascii")
            res.append((prp, prp, "ok" if png_b64 == s else "tampered",
                        "" if png_b64 == s else "png 与 qr_data.txt 不一致"))
        else:
            res.append((prp, prp, "missing", "文件不存在"))
    else:
        res.append((qrp, qrp, "missing", "文件不存在"))

    sp = os.path.join(ROOT, "SIGNATURE.json")
    if os.path.isfile(sp):
        try:
            m = json.loads(read(sp))
            ok = (m.get("author") == AUTHOR_NAME and m.get("wechat") == AUTHOR_WECHAT
                  and m.get("marker") == MARKER)
            res.append(("SIGNATURE.json", "SIGNATURE.json",
                        "ok" if ok else "tampered", "" if ok else "署名字段被改"))
        except Exception as e:
            res.append(("SIGNATURE.json", "SIGNATURE.json", "tampered", "解析失败：%s" % e))
    else:
        res.append(("SIGNATURE.json", "SIGNATURE.json", "missing", "文件不存在"))

    # 全仓库不得残留旧 email（用户已要求删除）
    # 注意：排除校验脚本自身——本检查的字面量就在其中，否则自指误报
    stale = []
    for rp in protected_files():
        if rp == "tools/signature_guard.py":
            continue
        try:
            if "doublebean@vip.qq.com" in read(os.path.join(ROOT, rp)):
                stale.append(rp)
        except Exception:
            pass
    res.append(("no-stale-email", "(all files)",
                "ok" if not stale else "tampered",
                "" if not stale else "残留旧 email：%s" % stale))

    return res


# ================================================================ 命令
def cmd_inject(log):
    log.append("== inject ==")
    log.append("  qr-recover: %s" % (recover_qr(log) or "skip"))
    log.append("  stale     : %s" % (inject_stale_email(log) or "skip"))
    log.append("  html      : %s" % (inject_html(log) or "skip"))
    log.append("  data.js   : %s" % (inject_js_data(log) or "skip"))
    log.append("  data.json : %s" % (inject_json_data(log) or "skip"))
    log.append("  static    : %s" % (create_static_files(log) or "skip"))
    log.append("  assets    : %s" % (inject_assets(log) or "skip"))
    py = inject_py(log)
    log.append("  python    : %d file(s) %s" % (len(py), list(py.keys())))
    md = inject_md(log)
    log.append("  markdown  : %d file(s) %s" % (len(md), list(md.keys())))
    yml = inject_yml(log)
    log.append("  workflow  : %s" % (yml or "skip"))
    m = write_manifest(log)
    log.append("  manifest  : SIGNATURE.json (%d files tracked)" % len(m["sha256"]))


def cmd_check(log, verbose=True):
    log.append("== check ==")
    comps = collect_components()
    bad = [c for c in comps if c[2] != "ok"]
    good = [c for c in comps if c[2] == "ok"]

    log.append("  components : %d total, %d ok, %d bad" % (len(comps), len(good), len(bad)))
    if verbose:
        for name, rp, st, note in comps:
            if st == "ok":
                log.append("    [ok]       %s" % name)
            else:
                log.append("    [%-9s] %s%s" % (st.upper(), name,
                                                ("  <- " + note) if note else ""))
    if bad:
        log.append("")
        log.append("  受影响文件：")
        for rp in sorted(set(c[1] for c in bad)):
            log.append("    %s" % rp)

    sp = os.path.join(ROOT, "SIGNATURE.json")
    if os.path.isfile(sp):
        try:
            man = json.loads(read(sp))
            drift = [rp for rp, h in man.get("sha256", {}).items()
                     if exists(rp) and sha256(os.path.join(ROOT, rp)) != h]
            log.append("  drift      : %d %s" % (len(drift), drift[:8]))
        except Exception:
            pass

    log.append("")
    if bad:
        log.append("RESULT  : FAIL — 署名不完整或被篡改，禁止部署。")
        log.append("          制作人：徐徐   微信：doublebean_vip")
        log.append("          修复：python tools/signature_guard.py inject")
        return 1
    log.append("RESULT  : PASS — 全部 %d 处署名完整。制作人：徐徐（微信：%s）"
               % (len(good), AUTHOR_WECHAT))
    return 0


def cmd_list(log):
    log.append("== protected components ==")
    for name, rp, st, note in collect_components():
        log.append("  [%-9s] %-42s  (%s)" % (st, name, rp))


def main():
    log = []
    action = (sys.argv[1] if len(sys.argv) > 1 else "check").lower()
    quiet = "-q" in sys.argv[2:] or "--quiet" in sys.argv[2:]

    if action == "inject":
        cmd_inject(log)
        code = cmd_check(log, verbose=not quiet)
    elif action == "list":
        cmd_list(log)
        code = 0
    elif action == "check":
        code = cmd_check(log, verbose=not quiet)
    else:
        log.append("unknown action: %s (use inject|check|list)" % action)
        code = 2

    text = "\n".join(log) + "\n"
    try:
        with io.open(os.path.join(ROOT, "tools", "_guard_log.txt"), "w", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(text)
    except Exception:
        pass
    return code


if __name__ == "__main__":
    sys.exit(main())
