#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
水利工程安全题库转换器（准确版）
按 一、单项选择题 / 二、多项选择题 / 三、判断题 分节，
再按题号切块解析，生成 questions.json 与 questions-data.js。
"""

import json
import re
import sys

# 题号行：以数字开头，后跟 、 . ． 等
QNUM_RE = re.compile(r'^\s*(\d+)[、，．.\.]')
# 答案：A 或 答案：ABC（兼容全角冒号）
ANSWER_RE = re.compile(r'答案[：:\s]*([A-EＡ-Ｅ]+)')
# 选项标记切分点：A、 B、 C． 等（容忍字母与标点间的空格，如 "A 、7"）
OPTION_SPLIT_RE = re.compile(r'(?=[A-E]\s*[、，．.\.])')
OPTION_MATCH_RE = re.compile(r'^([A-E])\s*[、，．.\.]\s*(.+)$', re.DOTALL)


def normalize_letter(s):
    """全角字母转半角"""
    out = []
    for ch in s:
        code = ord(ch)
        if 0xFF21 <= code <= 0xFF25:  # Ａ-Ｅ
            out.append(chr(code - 0xFF21 + ord('A')))
        else:
            out.append(ch)
    return ''.join(out)


def split_into_blocks(lines):
    """把一节内的行按题号切分成若干题块"""
    blocks = []
    current = None
    for line in lines:
        if QNUM_RE.match(line):
            if current is not None:
                blocks.append(current)
            current = [line]
        else:
            if current is not None:
                current.append(line)
    if current is not None:
        blocks.append(current)
    return blocks


def parse_choice_block(block, multi=False):
    """解析单选/多选题块"""
    text = ' '.join(l.strip() for l in block if l.strip())
    # 折叠畸形的题号串 "2、3、4、...、397、真正题干"
    text = re.sub(r'^(?:\s*\d+[、，．.\.]\s*){2,}', '', text)
    # 去掉正常题号前缀
    text = QNUM_RE.sub('', text, count=1).strip()

    # 提取答案：优先 答案：X，其次括号内 （D）/（AB）
    answer_letters = None
    special_note = ''
    m = ANSWER_RE.search(text)
    if m:
        answer_letters = normalize_letter(m.group(1))
        text = ANSWER_RE.sub('', text).strip()
    else:
        pm = re.search(r'[（(]\s*([A-EＡ-Ｅ]{1,5})\s*[）)]', text)
        if pm:
            answer_letters = normalize_letter(pm.group(1))
            # 把答案括号替换为空白占位，使题干显示空括号
            text = text[:pm.start()] + '（  ）' + text[pm.end():]

    # 清理残留的非字母答案标注（如 "答案：全错。"），避免污染选项
    if re.search(r'答案[：:]\s*全[错對对]', text):
        special_note = '原题标注答案为"全错"（四个选项均不正确）'
    text = re.sub(r'答案[：:].*$', '', text).strip()

    # 切分问题与选项
    parts = OPTION_SPLIT_RE.split(text)
    question = parts[0].strip()
    options = []
    for p in parts[1:]:
        mm = OPTION_MATCH_RE.match(p.strip())
        if mm:
            opt_text = mm.group(2).strip()
            options.append(f"{mm.group(1)}. {opt_text}")

    if not question or len(options) < 2:
        return None, False

    has_answer = answer_letters is not None
    if multi:
        if answer_letters:
            correct = sorted(set(ord(c) - ord('A') for c in answer_letters))
            # 过滤越界
            correct = [i for i in correct if 0 <= i < len(options)]
            if not correct:
                correct = [0]
        else:
            correct = [0]
    else:
        if answer_letters:
            idx = ord(answer_letters[0]) - ord('A')
            correct = idx if 0 <= idx < len(options) else 0
        else:
            correct = 0

    return {
        'question': question,
        'options': options,
        'correct': correct,
        'explanation': special_note
    }, (has_answer or bool(special_note))


def parse_judgement_block(block):
    """解析判断题块"""
    text = ' '.join(l.strip() for l in block if l.strip())
    text = re.sub(r'^(?:\s*\d+[、，．.\.]\s*){2,}', '', text)
    text = QNUM_RE.sub('', text, count=1).strip()

    correct = None
    # 括号内正误标记（含变体）
    if re.search(r'[（(]\s*(正确|对|√|✓|[ＴT])\s*[）)]', text):
        correct = 0
    elif re.search(r'[（(]\s*(错误|错|×|✗|[ＦF])\s*[）)]', text):
        correct = 1
    else:
        # 末尾裸正误标记
        tail = text[-6:]
        if re.search(r'(正确|√|✓)\s*$', tail):
            correct = 0
        elif re.search(r'(错误|×|✗)\s*$', tail):
            correct = 1

    # 去掉答案标记
    question = re.sub(r'[（(]\s*(正确|错误|对|错|√|×|✓|✗|[ＴＦTF])\s*[）)]', '', text)
    question = re.sub(r'\s*(正确|错误)\s*$', '', question).strip()

    if not question:
        return None, False

    has_answer = correct is not None
    if correct is None:
        correct = 0

    return {
        'question': question,
        'options': ['A. 正确', 'B. 错误'],
        'correct': correct,
        'explanation': ''
    }, has_answer


def parse_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()

    # 按节切分
    single_m = re.search(r'一、单项选择题(.*?)(?=二、多项选择题|$)', content, re.DOTALL)
    multi_m = re.search(r'二、多项选择题(.*?)(?=三、判断题|$)', content, re.DOTALL)
    judge_m = re.search(r'三、判断题(.*?)(?=四、|$)', content, re.DOTALL)

    data = {}
    stats = {}

    if single_m:
        lines = single_m.group(1).splitlines()
        blocks = split_into_blocks(lines)
        qs, miss = [], 0
        for b in blocks:
            q, ok = parse_choice_block(b, multi=False)
            if q:
                qs.append(q)
                if not ok:
                    miss += 1
        data['单选题'] = qs
        stats['单选题'] = (len(blocks), len(qs), miss)

    if multi_m:
        lines = multi_m.group(1).splitlines()
        blocks = split_into_blocks(lines)
        qs, miss = [], 0
        for b in blocks:
            q, ok = parse_choice_block(b, multi=True)
            if q:
                qs.append(q)
                if not ok:
                    miss += 1
        data['多选题'] = qs
        stats['多选题'] = (len(blocks), len(qs), miss)

    if judge_m:
        lines = judge_m.group(1).splitlines()
        blocks = split_into_blocks(lines)
        qs, miss = [], 0
        for b in blocks:
            q, ok = parse_judgement_block(b)
            if q:
                qs.append(q)
                if not ok:
                    miss += 1
        data['判断题'] = qs
        stats['判断题'] = (len(blocks), len(qs), miss)

    return data, stats


def main():
    input_file = sys.argv[1] if len(sys.argv) > 1 else '题库.txt'

    print('=' * 60)
    print('📚 水利工程安全题库转换器')
    print('=' * 60)
    print(f'\n📖 读取: {input_file}')

    data, stats = parse_file(input_file)

    print('\n📊 转换统计 (题号数 / 成功解析 / 缺答案):')
    total = 0
    for cat, (blocks, parsed, miss) in stats.items():
        print(f'  {cat}: {blocks} / {parsed} / 缺答案{miss}')
        total += parsed
    print(f'  总计: {total} 题')

    # 写 JSON
    with open('questions.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print('\n✅ 已保存到: questions.json')

    # 写 JS（双击 index.html 可用）
    with open('questions-data.js', 'w', encoding='utf-8') as f:
        f.write('window.QUIZ_DATA = ' + json.dumps(data, ensure_ascii=False, indent=2) + ';')
    print('✅ 已保存到: questions-data.js')
    print('\n📝 下一步: 双击 index.html 即可做题，或刷新浏览器(F5)')


if __name__ == '__main__':
    main()
