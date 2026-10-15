#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SIG:BEGIN:header
# ============================================================
#  署名信息 / ATTRIBUTION  —  请勿删除 (DO NOT REMOVE)
#  制作人：徐徐
#  email：doublebean@vip.qq.com
#  Copyright (c) 2026 徐徐 <doublebean@vip.qq.com>. All Rights Reserved.
# ============================================================
# SIG:END:header
# SIG:BEGIN:header
# SIG:END:header
"""
署名注入 / 校验工具 (Signature Guard)

制作人：徐徐   email：doublebean@vip.qq.com

设计要点
--------
每一处署名都是一个「带哨兵标记的规范块」：

    <!-- SIG:BEGIN:footer -->
    ...规范内容...
    <!-- SIG:END:footer -->

因此校验是**逐组件、逐字**的：
  * 删掉任何一处署名        -> 哨兵找不到        -> FAIL
  * 把「徐徐」改成别的名字   -> 内容与规范版不符  -> FAIL
  * 只删块里的一行           -> 内容与规范版不符  -> FAIL

修复（inject）采用「剥离旧块 + 重插规范块」，所以是**字节级还原**，
且天然幂等（重复运行不会产生重复头部）。

用法
----
    python tools/signature_guard.py inject   # 注入/修复所有署名（幂等）
    python tools/signature_guard.py check    # 校验；不完整则退出码 1（CI 用）
    python tools/signature_guard.py list     # 列出受保护组件清单
"""

import hashlib
import io
import json
import os
import re
import sys

# ================================================================ 署名常量
AUTHOR_NAME = "徐徐"
AUTHOR_EMAIL = "doublebean@vip.qq.com"
COPYRIGHT = "Copyright (c) 2026 徐徐 <doublebean@vip.qq.com>. All Rights Reserved."
MARKER = "制作人：徐徐"

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


def exists(rp):
    return os.path.isfile(os.path.join(ROOT, rp))


# ================================================================ 哨兵块机制
# 不同文件类型用不同的注释语法包裹哨兵
COMMENT = {
    "html": ("<!-- SIG:BEGIN:%s -->", "<!-- SIG:END:%s -->"),
    "css": ("/* SIG:BEGIN:%s */", "/* SIG:END:%s */"),
    "js": ("/* SIG:BEGIN:%s */", "/* SIG:END:%s */"),
    "py": ("# SIG:BEGIN:%s", "# SIG:END:%s"),
    "yml": ("# SIG:BEGIN:%s", "# SIG:END:%s"),
}


def block_regex(kind, name):
    b, e = COMMENT[kind]
    b = re.escape(b % name)
    e = re.escape(e % name)
    return re.compile(b + r"\n(.*?)\n" + e, re.DOTALL)


def make_block(kind, name, body):
    b, e = COMMENT[kind]
    return (b % name) + "\n" + body + "\n" + (e % name)


def find_block(s, kind, name):
    return block_regex(kind, name).search(s)


def upsert_block(s, kind, name, body, anchor=None, before=False):
    """插入或修复一个哨兵块。

    返回 (新文本, 动作)；动作 ∈ {'', 'inserted', 'repaired', 'ANCHOR-NOT-FOUND'}。
    块已存在且逐字相同 -> 不改动。
    块已存在但被篡改   -> 整块替换为规范版（repaired）。
    块不存在           -> 在 anchor 处插入（inserted）。
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
        # 压缩锚点前残留空行为恰好一个 \n，保证从任意篡改态收敛到同一形态
        head = s[:i].rstrip("\n")
        if head:
            head += "\n"
        return head + full + "\n" + s[i:], "inserted"
    j = i + len(anchor)
    # 压缩锚点后残留空行为恰好一个 \n
    tail = "\n" + s[j:].lstrip("\n")
    return s[:j] + "\n" + full + tail, "inserted"


def check_block(s, kind, name, body):
    """返回 'ok' / 'tampered' / 'missing'。"""
    full = make_block(kind, name, body)
    m = find_block(s, kind, name)
    if not m:
        return "missing"
    return "ok" if m.group(0) == full else "tampered"


def squeeze_blanks(lines, idx, keep=0):
    """压缩 lines[idx] 起连续的空白行，使插入形态收敛（保证幂等 + 可字节级还原）。

    篡改者删掉署名块后往往会留下多余空行；统一压缩后再插入规范块，
    无论被删成什么样，结果都收敛到同一形态。
    """
    n = 0
    while idx + n < len(lines) and lines[idx + n].strip() == "":
        n += 1
    if n > keep:
        del lines[idx + keep: idx + n]
    return lines


# ================================================================ 规范内容
HTML_META_BODY = """    <!-- ============================================================
         署名信息 / ATTRIBUTION  —  请勿删除 (DO NOT REMOVE)
         制作人：徐徐
         email：doublebean@vip.qq.com
         Copyright (c) 2026 徐徐 <doublebean@vip.qq.com>. All Rights Reserved.
         本文件受 tools/signature_guard.py 与 CI 工作流保护：
         删除或篡改署名会导致构建失败、GitHub Pages 停止部署。
         ============================================================ -->
    <meta name="author" content="徐徐 <doublebean@vip.qq.com>">
    <meta name="copyright" content="Copyright (c) 2026 徐徐. All Rights Reserved.">
    <meta name="creator" content="徐徐 / doublebean@vip.qq.com">"""

HTML_CSS_BODY = """        /* ===== 署名样式（请勿删除 / DO NOT REMOVE） ===== */
        .site-footer {
            margin-top: 30px;
            padding-top: 16px;
            border-top: 1px solid #eee;
            text-align: center;
            color: #888;
            font-size: 13px;
            line-height: 1.8;
        }

        .site-footer .sig-line strong {
            color: #667eea;
            font-weight: 600;
        }

        .site-footer a {
            color: #888;
            text-decoration: none;
        }

        .site-footer a:hover {
            color: #667eea;
            text-decoration: underline;
        }

        .site-footer .sig-copy {
            font-size: 12px;
            color: #bbb;
            margin-top: 4px;
        }"""

HTML_FOOTER_BODY = """        <!-- ===== 署名（请勿删除 / DO NOT REMOVE）=====
             制作人：徐徐   email：doublebean@vip.qq.com -->
        <footer class="site-footer" id="siteFooter">
            <div class="sig-line">制作人：<strong>徐徐</strong></div>
            <div class="sig-line">email：<a href="mailto:doublebean@vip.qq.com">doublebean@vip.qq.com</a></div>
            <div class="sig-copy">Copyright &copy; 2026 徐徐. All Rights Reserved.</div>
        </footer>"""

HTML_GUARD_BODY = """        /* ============================================================
         *  署名保护 / SIGNATURE GUARD  —  请勿删除 (DO NOT REMOVE)
         *  制作人：徐徐
         *  email：doublebean@vip.qq.com
         *  Copyright (c) 2026 徐徐. All Rights Reserved.
         *
         *  作用：即使有人从 HTML 里删掉页脚署名，本段代码也会在运行时
         *  自动把它重建回来，并在控制台告警。
         * ============================================================ */
        const AUTHOR_SIGNATURE = Object.freeze({
            name: '徐徐',
            email: 'doublebean@vip.qq.com',
            copyright: 'Copyright © 2026 徐徐. All Rights Reserved.'
        });

        (function signatureGuard() {
            const FOOTER_ID = 'siteFooter';
            const WARN = '[署名保护] 检测到署名被移除，已自动恢复。' +
                         '制作人：徐徐 <doublebean@vip.qq.com>';

            function buildFooter() {
                const f = document.createElement('footer');
                f.className = 'site-footer';
                f.id = FOOTER_ID;
                f.innerHTML =
                    '<div class="sig-line">制作人：<strong>' + AUTHOR_SIGNATURE.name + '</strong></div>' +
                    '<div class="sig-line">email：<a href="mailto:' + AUTHOR_SIGNATURE.email + '">' +
                    AUTHOR_SIGNATURE.email + '</a></div>' +
                    '<div class="sig-copy">' + AUTHOR_SIGNATURE.copyright + '</div>';
                return f;
            }

            function ensure() {
                if (document.getElementById(FOOTER_ID)) return;
                const host = document.querySelector('.container') || document.body;
                if (!host) return;
                host.appendChild(buildFooter());
                try { console.warn('%c' + WARN, 'color:#c0392b;font-weight:bold;'); } catch (e) {}
            }

            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', ensure);
            } else {
                ensure();
            }

            // 监听 DOM 变化：署名节点被删除时立即恢复
            try {
                new MutationObserver(function () { ensure(); })
                    .observe(document.documentElement, { childList: true, subtree: true });
            } catch (e) { /* 极老浏览器忽略 */ }

            // 控制台常驻署名
            try {
                console.log(
                    '%c题库系统%c  制作人：徐徐   email：doublebean@vip.qq.com',
                    'background:#667eea;color:#fff;padding:2px 8px;border-radius:3px;font-weight:bold;',
                    'color:#333;'
                );
                console.log('%c' + AUTHOR_SIGNATURE.copyright, 'color:#999;');
            } catch (e) {}
        })();"""

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
 *  email：doublebean@vip.qq.com
 *  Copyright (c) 2026 徐徐 <doublebean@vip.qq.com>. All Rights Reserved.
 * ============================================================ */"""

JS_TAIL_BODY = """try {
    window.QUIZ_DATA._signature = Object.freeze({
        author: '徐徐',
        email: 'doublebean@vip.qq.com',
        copyright: 'Copyright (c) 2026 徐徐 <doublebean@vip.qq.com>. All Rights Reserved.',
        notice: '制作人：徐徐 — 请勿删除本署名信息 / DO NOT REMOVE THIS ATTRIBUTION'
    });
} catch (e) {}"""

JSON_SIG = {
    "author": AUTHOR_NAME,
    "email": AUTHOR_EMAIL,
    "copyright": COPYRIGHT,
    "notice": "制作人：徐徐 — 请勿删除本署名信息 / DO NOT REMOVE THIS ATTRIBUTION",
}

PY_HEADER_BODY = """# ============================================================
#  署名信息 / ATTRIBUTION  —  请勿删除 (DO NOT REMOVE)
#  制作人：徐徐
#  email：doublebean@vip.qq.com
#  Copyright (c) 2026 徐徐 <doublebean@vip.qq.com>. All Rights Reserved.
# ============================================================"""

# 注意：「制作人：徐徐」必须是连续纯文本（不能加粗体标记），
# 否则 MARKER 精确匹配不上。
MD_HEADER_BODY = """> **署名 / Attribution**
> 制作人：徐徐 　email：<doublebean@vip.qq.com>
> Copyright (c) 2026 徐徐. All Rights Reserved. — 请勿删除本署名信息。"""

YML_HEADER_BODY = """# ============================================================
#  署名信息 / ATTRIBUTION  —  请勿删除 (DO NOT REMOVE)
#  制作人：徐徐
#  email：doublebean@vip.qq.com
#  Copyright (c) 2026 徐徐 <doublebean@vip.qq.com>. All Rights Reserved.
# ============================================================"""

# pages.yml 里「部署前强制校验署名」的步骤。
# 用 YAML 注释形式的哨兵块包裹，因此被篡改后能整块替换而不会重复插入。
YML_GUARD_BODY = """      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      # 署名校验：缺失或被篡改则部署中止（制作人：徐徐 / doublebean@vip.qq.com）
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

LICENSE_TEXT = """Copyright (c) 2026 徐徐 <doublebean@vip.qq.com>

保留所有权利 / All Rights Reserved.

--------------------------------------------------------------------
署名与使用许可 (Attribution & Terms of Use)
--------------------------------------------------------------------

1. 本仓库（含题库系统网页、题库数据、转换脚本、文档等全部内容）的
   作者与著作权人为 **徐徐**（email: doublebean@vip.qq.com）。

2. 任何复制、分发、展示或二次使用本仓库内容的行为，**必须**在所有
   副本中完整保留本文件、`AUTHORS.md`、`SIGNATURE.json` 以及各源文件
   中的署名信息（"制作人：徐徐 / doublebean@vip.qq.com"）。

3. **禁止删除、隐藏、替换或伪造署名信息**，包括但不限于：
   - 删除或注释掉源文件中的署名头部；
   - 移除网页页脚署名或 `AUTHOR_SIGNATURE` 运行时常量；
   - 移除 `<meta name="author">` 等元数据标签；
   - 删除 `_signature` 数据字段；
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
  - `main` 分支已启用保护规则，禁止强制推送与分支删除。

校验采用「哨兵块逐字比对」：每处署名都被 SIG:BEGIN / SIG:END 标记包裹，
删除其中任何一行、或把作者名改成别的字，都会被检出。

--------------------------------------------------------------------
联系方式 / Contact
--------------------------------------------------------------------
制作人：徐徐
email：doublebean@vip.qq.com
"""

AUTHORS_TEXT = """# 署名 / AUTHORS

| 角色 | 姓名 | 邮箱 |
| ---- | ---- | ---- |
| 制作人 (Author) | **徐徐** | <doublebean@vip.qq.com> |

**Copyright (c) 2026 徐徐 <doublebean@vip.qq.com>. All Rights Reserved.**

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
| 2 | `index.html` 页脚 | 用户打开页面即可见的署名 |
| 3 | `index.html` `AUTHOR_SIGNATURE` + MutationObserver | 运行时自愈：页脚被删会自动重建并告警 |
| 4 | `questions-data.js` / `questions.json` 的 `_signature` | 数据文件自带署名，脱离网页也能溯源 |
| 5 | GitHub Actions（两个工作流） | 署名被删/被改则 CI 失败，Pages 停止部署 |

校验命令：

```bash
python tools/signature_guard.py check    # 校验，不完整则退出码 1
python tools/signature_guard.py inject   # 注入 / 修复（幂等，字节级还原）
python tools/signature_guard.py list     # 列出全部受保护组件
```

---

制作人：徐徐 　email：doublebean@vip.qq.com
"""

GUARD_WORKFLOW = """# ============================================================
#  署名信息 / ATTRIBUTION  —  请勿删除 (DO NOT REMOVE)
#  制作人：徐徐
#  email：doublebean@vip.qq.com
#  Copyright (c) 2026 徐徐 <doublebean@vip.qq.com>. All Rights Reserved.
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
           "AUTHORS.md", "SIGNATURE.json",
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
def inject_html(log):
    p = os.path.join(ROOT, "index.html")
    if not os.path.isfile(p):
        log.append("  index.html 不存在，跳过")
        return []
    s = read(p)
    orig = s
    acts = []

    # 1) head 元数据：插在 viewport meta 之后
    s, a = upsert_block(
        s, "html", "meta", HTML_META_BODY,
        anchor='<meta name="viewport" content="width=device-width, initial-scale=1.0">',
    )
    if a:
        acts.append("meta:" + a)

    # 2) 页脚样式：插在 </style> 之前
    s, a = upsert_block(s, "css", "css", HTML_CSS_BODY, anchor="    </style>", before=True)
    if a:
        acts.append("css:" + a)

    # 3) 页脚 DOM：插在 .container 结束前（完成区块之后）
    fm = find_block(s, "html", "footer")
    foot_full = make_block("html", "footer", HTML_FOOTER_BODY)
    if fm:
        if fm.group(0) != foot_full:
            s = s[: fm.start()] + foot_full + s[fm.end():]
            acts.append("footer:repaired")
    else:
        # 锚点用正则，容忍块被删除后残留的空行
        m = FOOT_ANCHOR_RE.search(s)
        if m:
            s = s[: m.start()] + m.group(1) + "\n" + foot_full + "\n" + m.group(2) + s[m.end():]
            acts.append("footer:inserted")
        else:
            acts.append("footer:ANCHOR-NOT-FOUND")

    # 4) 运行时保护脚本：插在最后一个 </script> 之前
    s, a = upsert_block(s, "js", "guard", HTML_GUARD_BODY,
                        anchor="    </script>\n</body>", before=True)
    if a:
        acts.append("guard:" + a)

    # 5) stripSignatureMeta：保证 _signature 不出现在分类按钮里
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

    # 6) 接线自愈：函数在但调用被改回原样时，重新接上
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

    # 头部注释块（文件最开头）
    head_full = make_block("js", "header", JS_HEADER_BODY)
    hm = find_block(s, "js", "header")
    if hm:
        if hm.group(0) != head_full:
            s = s[: hm.start()] + head_full + s[hm.end():]
            acts.append("header:repaired")
    else:
        s = head_full + "\n" + s.lstrip("\n")
        acts.append("header:inserted")

    # 尾部 _signature 块
    tail_full = make_block("js", "sig", JS_TAIL_BODY)
    tm = find_block(s, "js", "sig")
    if tm:
        if tm.group(0) != tail_full:
            s = s[: tm.start()] + tail_full + s[tm.end():]
            acts.append("sig:repaired")
    else:
        # 去掉历史遗留的裸 _signature 尾巴（早期版本插入的），避免重复
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
    # 重建：_signature 永远排在第一个键；丢弃所有下划线开头的键
    # （被改名的旧签名字段如 _zzz 也会被清掉，保证收敛到规范形态）
    new = {"_signature": JSON_SIG}
    for k, v in d.items():
        if not k.startswith("_"):
            new[k] = v
    write(p, json.dumps(new, ensure_ascii=False, indent=2) + "\n")
    json.loads(read(p))  # 回读校验
    return ["sig:repaired" if had else "sig:inserted"]


def inject_py(log):
    out = {}
    for p in py_files():
        raw = read(p)
        # 先 upsert（块在则修复/跳过）；只有块完全不在时才剥离旧版无哨兵横幅
        s, a = upsert_block(raw, "py", "header", PY_HEADER_BODY)
        if a == "ANCHOR-NOT-FOUND":
            s = re.sub(
                r"^# =+\n#  署名信息 / ATTRIBUTION.*?\n# =+\n",
                "", s, flags=re.DOTALL | re.MULTILINE)
            # 插到 shebang / coding 声明之后
            lines = s.split("\n")
            idx = 0
            while idx < len(lines) and (lines[idx].startswith("#!") or "coding" in lines[idx]):
                idx += 1
            # 压缩块被删除后残留的空行，保证结果收敛到同一形态
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
        # 先 upsert；只有块完全不在时才剥离旧版无哨兵署名引用块
        s, a = upsert_block(raw, "html", "mdheader", MD_HEADER_BODY)
        if a == "ANCHOR-NOT-FOUND":
            s = re.sub(r"^> \*\*署名 / Attribution\*\*\n(?:> .*\n|\n)*?\n?", "", s)
            lines = s.split("\n")
            block = make_block("html", "mdheader", MD_HEADER_BODY)
            if lines and lines[0].startswith("# "):
                # 压缩残留空行后插入，形态固定为：标题 / 空行 / 块 / 空行
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
        # 先 upsert；只有块完全不在时才剥离旧版无哨兵横幅
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

        # 部署前强制校验（哨兵块包裹，被篡改则整块替换，不会重复插入）
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


def write_manifest(log):
    """SIGNATURE.json：署名 + 受保护文件指纹清单。"""
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
        "email": AUTHOR_EMAIL,
        "attribution": "制作人：徐徐 <doublebean@vip.qq.com>",
        "copyright": COPYRIGHT,
        "notice": "禁止删除、隐藏、替换或伪造署名信息。详见 LICENSE。",
        "marker": MARKER,
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

    # --- index.html 的 5 个组件 ---
    hp = os.path.join(ROOT, "index.html")
    if os.path.isfile(hp):
        s = read(hp)
        for name, kind, body in (("meta", "html", HTML_META_BODY),
                                 ("css", "css", HTML_CSS_BODY),
                                 ("footer", "html", HTML_FOOTER_BODY),
                                 ("guard", "js", HTML_GUARD_BODY),
                                 ("strip", "js", HTML_STRIP_BODY)):
            res.append(("index.html:%s" % name, "index.html",
                        check_block(s, kind, name, body), ""))
        # strip 必须真的被调用（定义 1 次 + 调用 2 次）
        used = s.count("stripSignatureMeta(")
        res.append(("index.html:strip-wired", "index.html",
                    "ok" if used >= 3 else "tampered",
                    "stripSignatureMeta 调用次数=%d（期望>=3）" % used))
    else:
        res.append(("index.html", "index.html", "missing", "文件不存在"))

    # --- questions-data.js ---
    jp = os.path.join(ROOT, "questions-data.js")
    if os.path.isfile(jp):
        s = read(jp)
        res.append(("questions-data.js:header", "questions-data.js",
                    check_block(s, "js", "header", JS_HEADER_BODY), ""))
        res.append(("questions-data.js:sig", "questions-data.js",
                    check_block(s, "js", "sig", JS_TAIL_BODY), ""))
        res.append(("questions-data.js:data-intact", "questions-data.js",
                    "ok" if "window.QUIZ_DATA = {" in s else "tampered",
                    "数据主体"))
    else:
        res.append(("questions-data.js", "questions-data.js", "missing", "文件不存在"))

    # --- questions.json ---
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

    # --- 整文件即规范内容的文件 ---
    for rp, text in (("LICENSE", LICENSE_TEXT),
                     ("AUTHORS.md", AUTHORS_TEXT),
                     (".github/workflows/signature-guard.yml", GUARD_WORKFLOW)):
        if not exists(rp):
            res.append((rp, rp, "missing", "文件不存在"))
        else:
            s = read(rp)
            res.append((rp, rp, "ok" if s == text else "tampered",
                        "" if s == text else "内容与规范版不符"))

    # --- pages.yml：头部块 + 部署校验步骤 + 步骤顺序 ---
    wp = os.path.join(ROOT, ".github", "workflows", "pages.yml")
    if os.path.isfile(wp):
        s = read(wp)
        res.append(("pages.yml:header", ".github/workflows/pages.yml",
                    check_block(s, "yml", "header", YML_HEADER_BODY), ""))
        gst = check_block(s, "yml", "deploy-guard", YML_GUARD_BODY)
        res.append(("pages.yml:deploy-guard", ".github/workflows/pages.yml", gst,
                    "" if gst == "ok" else "部署前校验步骤缺失或被篡改"))
        has_guard = "signature_guard.py check" in s
        if has_guard and "Deploy to GitHub Pages" in s:
            ok_order = s.index("signature_guard.py check") < s.index("Deploy to GitHub Pages")
            res.append(("pages.yml:guard-order", ".github/workflows/pages.yml",
                        "ok" if ok_order else "tampered",
                        "" if ok_order else "校验步骤被移到部署之后"))
    else:
        res.append(("pages.yml", ".github/workflows/pages.yml", "missing", "文件不存在"))

    # --- Python 文件头部块 ---
    for p in py_files():
        rp = rel(p)
        s = read(p)
        res.append(("%s:header" % rp, rp, check_block(s, "py", "header", PY_HEADER_BODY), ""))

    # --- Markdown 文件头部块 ---
    for p in md_files():
        rp = rel(p)
        s = read(p)
        res.append(("%s:header" % rp, rp, check_block(s, "html", "mdheader", MD_HEADER_BODY), ""))

    # --- SIGNATURE.json 自身 ---
    sp = os.path.join(ROOT, "SIGNATURE.json")
    if os.path.isfile(sp):
        try:
            m = json.loads(read(sp))
            ok = (m.get("author") == AUTHOR_NAME and m.get("email") == AUTHOR_EMAIL
                  and m.get("marker") == MARKER)
            res.append(("SIGNATURE.json", "SIGNATURE.json",
                        "ok" if ok else "tampered", "" if ok else "署名字段被改"))
        except Exception as e:
            res.append(("SIGNATURE.json", "SIGNATURE.json", "tampered", "解析失败：%s" % e))
    else:
        res.append(("SIGNATURE.json", "SIGNATURE.json", "missing", "文件不存在"))

    return res


# ================================================================ 命令
def cmd_inject(log):
    log.append("== inject ==")
    log.append("  html      : %s" % (inject_html(log) or "skip"))
    log.append("  data.js   : %s" % (inject_js_data(log) or "skip"))
    log.append("  data.json : %s" % (inject_json_data(log) or "skip"))
    log.append("  static    : %s" % (create_static_files(log) or "skip"))
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

    # 指纹漂移（仅提示，不作为失败条件）
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
        log.append("          制作人：徐徐   email：doublebean@vip.qq.com")
        log.append("          修复：python tools/signature_guard.py inject")
        return 1
    log.append("RESULT  : PASS — 全部 %d 处署名完整。制作人：徐徐 <%s>"
               % (len(good), AUTHOR_EMAIL))
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
    # 自己写日志文件（避免 PowerShell 重定向产生 UTF-16）
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
