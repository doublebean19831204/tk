#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
题库格式转换工具
支持单选题、多选题、判断题的自动转换
"""

import json
import re

def split_options_line(line):
    """将一行中多个选项拆分为标准选项列表"""
    parts = re.split(r'(?=[A-E][、．.])', line)
    options = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        match = re.match(r'^([A-E])[、．.]?\s*(.+)$', part)
        if match:
            text = match.group(2).strip()
            # 如果选项行里包含答案，去掉答案部分
            text = re.split(r'答案[:：]', text)[0].strip()
            if text:
                options.append(f"{match.group(1)}. {text}")
    return options


def extract_answer(line):
    if not line:
        return None, 'single'

    line = line.strip()
    if '（正确）' in line or line == '正确':
        return 0, 'judgement'
    if '（错误）' in line or line == '错误':
        return 1, 'judgement'

    answer_match = re.search(r'答案[：:]\s*([A-E]+)', line, re.IGNORECASE)
    if answer_match:
        answer_str = answer_match.group(1).upper()
        if len(answer_str) > 1:
            return [ord(c) - ord('A') for c in answer_str], 'multiple'
        return ord(answer_str) - ord('A'), 'single'

    # 未识别答案，尝试直接读取字母
    letters = re.findall(r'\b([A-E])\b', line)
    if letters:
        if len(letters) > 1:
            return [ord(c) - ord('A') for c in letters], 'multiple'
        return ord(letters[0]) - ord('A'), 'single'

    return None, 'single'


def parse_quiz_text(text):
    """
    解析题目文本并转换为JSON格式
    支持格式：
    - 单选题：选项用 A、B、C、D 标记
    - 多选题：选项用 A、B、C、D、E 标记，答案用AB、ABC等
    - 判断题：答案是（正确）或（错误）
    """

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    questions = []
    i = 0

    while i < len(lines):
        line = lines[i]

        if re.match(r'^[\d]+[、、.]', line):
            question_text = re.sub(r'^[\d]+[、、.]\s*', '', line).strip()
            question_text = question_text.rstrip('（）')

            options = []
            answer_line = None
            i += 1

            while i < len(lines):
                next_line = lines[i]
                if re.match(r'^[\d]+[、、.]', next_line):
                    break

                if '答案' in next_line or '正确' in next_line or '错误' in next_line:
                    # 识别答案，也可能和选项在同一行
                    answer_line = next_line
                    options.extend(split_options_line(next_line))
                    i += 1
                    continue

                line_options = split_options_line(next_line)
                if line_options:
                    options.extend(line_options)
                    i += 1
                    continue

                i += 1

            if not options:
                continue

            correct_answer, question_type = extract_answer(answer_line)

            if question_type == 'single' and len(options) == 2 and any('正确' in opt or '错误' in opt for opt in options):
                question_type = 'judgement'

            if question_type == 'judgement':
                options = ['A. 正确', 'B. 错误']
                if correct_answer not in (0, 1):
                    correct_answer = 0

            if correct_answer is None:
                question_type = 'single'
                correct_answer = 0

            explanation = f"这是一道{ {'single':'单选', 'multiple':'多选', 'judgement':'判断'}.get(question_type, '单选') }题。"

            question_obj = {
                'question': question_text,
                'options': options,
                'correct': correct_answer,
                'explanation': explanation,
                'type': question_type
            }

            questions.append(question_obj)
        else:
            i += 1

    return questions

def create_json_from_questions(questions, category="题库"):
    """创建JSON结构"""

    # 按类型分组
    grouped = {}
    for q in questions:
        if q['type'] not in grouped:
            grouped[q['type']] = []
        grouped[q['type']].append(q)

    # 为多选题的答案转换格式
    json_data = {}

    for q_type, q_list in grouped.items():
        cat_name = category
        if q_type == 'single':
            cat_name = f"{category}(单选)"
        elif q_type == 'multiple':
            cat_name = f"{category}(多选)"
        elif q_type == 'judgement':
            cat_name = f"{category}(判断)"

        json_data[cat_name] = []

        for q in q_list:
            if q_type == 'multiple' and isinstance(q['correct'], str):
                # 多选题：答案是字母组合，需要转换为索引数组
                q['correct'] = [ord(c) - ord('A') for c in q['correct']]

            json_data[cat_name].append({
                'question': q['question'],
                'options': q['options'],
                'correct': q['correct'],
                'explanation': q['explanation']
            })

    return json_data

if __name__ == '__main__':
    import sys
    import os

    print("=" * 60)
    print("📚 题库格式转换工具")
    print("=" * 60)

    # 处理命令行参数
    if len(sys.argv) < 2:
        print("\n使用方法:")
        print("  python 题库转换器.py <输入文件> [输出文件] [分类名]")
        print("\n示例:")
        print("  python 题库转换器.py 题库.txt questions.json 水利工程安全")
        print("\n如果不指定输出文件，将输出到标准输出")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    category = sys.argv[3] if len(sys.argv) > 3 else "题库"

    # 读取输入文件
    if not os.path.exists(input_file):
        print(f"❌ 错误：找不到文件 {input_file}")
        sys.exit(1)

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception as e:
        print(f"❌ 读取文件失败: {e}")
        sys.exit(1)

    # 转换
    print(f"\n📖 读取: {input_file}")
    questions = parse_quiz_text(text)
    print(f"✓ 识别到 {len(questions)} 道题目")

    json_data = create_json_from_questions(questions, category)

    # 统计信息
    print("\n分类统计:")
    total = 0
    for cat, qs in json_data.items():
        print(f"  {cat}: {len(qs)} 题")
        total += len(qs)
    print(f"  总计: {total} 题")

    # 输出
    json_str = json.dumps(json_data, ensure_ascii=False, indent=2)

    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_str)
            print(f"\n✅ 已保存到: {output_file}")
        except Exception as e:
            print(f"❌ 保存失败: {e}")
            sys.exit(1)
    else:
        print("\n" + "=" * 60)
        print(json_str)
        print("=" * 60)
