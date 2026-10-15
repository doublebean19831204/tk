# 署名 / AUTHORS

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
