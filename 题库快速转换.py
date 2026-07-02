#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
水利工程题库转换器
专门处理题库.txt格式
"""

import json
import re
import sys

def parse_quiz_file(filename):
    """解析题库文件"""

    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()

    # 分割不同类型的题目
    data = {}

    # 识别单项选择题
    single_choice_match = re.search(r'一、单项选择题(.*?)(?=二、|$)', content, re.DOTALL)
    if single_choice_match:
        single_text = single_choice_match.group(1)
        data['单选题'] = parse_single_choice(single_text)

    # 识别多项选择题
    multi_choice_match = re.search(r'二、多项选择题(.*?)(?=三、|$)', content, re.DOTALL)
    if multi_choice_match:
        multi_text = multi_choice_match.group(1)
        data['多选题'] = parse_multi_choice(multi_text)

    # 识别判断题
    judgment_match = re.search(r'三、判断题(.*?)(?=四、|$)', content, re.DOTALL)
    if judgment_match:
        judgment_text = judgment_match.group(1)
        data['判断题'] = parse_judgment(judgment_text)

    # 识别简答题（如果有）
    qa_match = re.search(r'四、简答题(.*?)(?=五、|$)', content, re.DOTALL)
    if qa_match:
        qa_text = qa_match.group(1)
        data['简答题'] = parse_qa(qa_text)

    return data

def parse_single_choice(text):
    """解析单选题"""
    questions = []

    # 分割各题
    lines = text.strip().split('\n')
    current_q = None
    current_options = []
    current_answer = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # 题号行
        if re.match(r'^\d+[、、.]', line):
            # 保存前一题
            if current_q:
                q = create_question(current_q, current_options, current_answer, 'single')
                if q:
                    questions.append(q)

            # 开始新题
            current_q = re.sub(r'^\d+[、、.]\s*', '', line)
            current_options = []
            current_answer = None

        # 选项行
        elif re.match(r'^[A-D][、、.)\s]', line):
            parts = re.split(r'[、、.)\s]\s*', line, 1)
            if len(parts) == 2:
                letter = parts[0]
                text_content = parts[1].strip()
                current_options.append(f"{letter}. {text_content}")

        # 答案行
        elif '答案' in line or line.startswith('答案'):
            match = re.search(r'[A-D]', line)
            if match:
                current_answer = ord(match.group(0)) - ord('A')

    # 保存最后一题
    if current_q:
        q = create_question(current_q, current_options, current_answer, 'single')
        if q:
            questions.append(q)

    return questions

def parse_multi_choice(text):
    """解析多选题"""
    questions = []

    lines = text.strip().split('\n')
    current_q = None
    current_options = []
    current_answer = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # 题号行
        if re.match(r'^\d+[、、.]', line):
            # 保存前一题
            if current_q:
                q = create_question(current_q, current_options, current_answer, 'multi')
                if q:
                    questions.append(q)

            # 开始新题
            current_q = re.sub(r'^\d+[、、.]\s*', '', line)
            current_options = []
            current_answer = None

        # 选项行
        elif re.match(r'^[A-E][、、.)\s]', line):
            parts = re.split(r'[、、.)\s]\s*', line, 1)
            if len(parts) == 2:
                letter = parts[0]
                text_content = parts[1].strip()
                current_options.append(f"{letter}. {text_content}")

        # 答案行
        elif '答案' in line or line.startswith('答案'):
            answers = re.findall(r'[A-E]', line)
            if answers:
                current_answer = [ord(a) - ord('A') for a in answers]

    # 保存最后一题
    if current_q:
        q = create_question(current_q, current_options, current_answer, 'multi')
        if q:
            questions.append(q)

    return questions

def parse_judgment(text):
    """解析判断题"""
    questions = []

    lines = text.strip().split('\n')
    current_q = None
    current_answer = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # 题号行
        if re.match(r'^\d+[、、.]', line):
            # 保存前一题
            if current_q:
                q = {
                    'question': current_q,
                    'options': ['A. 正确', 'B. 错误'],
                    'correct': current_answer,
                    'explanation': '请参考相关规定'
                }
                if q['correct'] is not None:
                    questions.append(q)

            # 开始新题
            current_q = re.sub(r'^\d+[、、.]\s*', '', line)
            current_answer = None

        # 答案行 - 包含括号
        elif '（正确）' in line or '正确' in line:
            current_answer = 0
        elif '（错误）' in line or '错误' in line:
            current_answer = 1

    # 保存最后一题
    if current_q:
        q = {
            'question': current_q,
            'options': ['A. 正确', 'B. 错误'],
            'correct': current_answer,
            'explanation': '请参考相关规定'
        }
        if q['correct'] is not None:
            questions.append(q)

    return questions

def parse_qa(text):
    """解析简答题"""
    questions = []

    lines = text.strip().split('\n')
    current_q = None
    current_answer = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # 题号行
        if re.match(r'^\d+[、、.]', line):
            # 保存前一题
            if current_q:
                q = {
                    'question': current_q,
                    'answer': current_answer,
                    'type': 'qa'
                }
                questions.append(q)

            # 开始新题
            current_q = re.sub(r'^\d+[、、.]\s*', '', line)
            current_answer = None

        # 答案行
        elif '答' in line or '答案' in line or current_q:
            if current_answer is None:
                current_answer = line
            else:
                current_answer += '\n' + line

    # 保存最后一题
    if current_q:
        q = {
            'question': current_q,
            'answer': current_answer,
            'type': 'qa'
        }
        questions.append(q)

    return questions

def create_question(question_text, options, answer, q_type):
    """创建题目对象"""

    if not question_text or not options or answer is None:
        return None

    return {
        'question': question_text.strip(),
        'options': options,
        'correct': answer,
        'explanation': '请参考相关规定'
    }

def main():
    if len(sys.argv) < 2:
        print("使用方法: python 题库快速转换.py 题库.txt")
        sys.exit(1)

    input_file = sys.argv[1]

    print("=" * 60)
    print("📚 题库转换工具")
    print("=" * 60)

    try:
        print(f"\n📖 读取文件: {input_file}")
        data = parse_quiz_file(input_file)

        # 统计
        print("\n📊 转换统计:")
        total = 0
        for category, questions in data.items():
            print(f"  {category}: {len(questions)} 题")
            total += len(questions)
        print(f"  总计: {total} 题")

        # 输出JSON
        output_file = "questions.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        print(f"\n✅ 已保存到: {output_file}")
        print("\n📝 下一步:")
        print("  1. 刷新浏览器 (F5)")
        print("  2. 打开 index.html 开始做题")

    except Exception as e:
        print(f"❌ 错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
