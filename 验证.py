#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JSON 题库文件验证工具
检查 questions.json 的格式是否正确
"""

import json
import os
import sys

def validate_quiz_json(filename="questions.json"):
    """验证题库JSON文件"""

    print("=" * 60)
    print("📝 JSON 题库验证工具")
    print("=" * 60)

    if not os.path.exists(filename):
        print(f"❌ 错误：找不到文件 {filename}")
        return False

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)

        print(f"✅ JSON 格式正确")
        print()

        # 统计信息
        total_questions = 0
        categories = []

        for category, questions in data.items():
            if not isinstance(questions, list):
                print(f"❌ 错误：分类 '{category}' 的值必须是列表")
                return False

            categories.append(category)
            total_questions += len(questions)

            print(f"📚 分类：{category}")
            print(f"   题目数：{len(questions)}")

            for i, q in enumerate(questions, 1):
                # 检查必需字段
                required_fields = ['question', 'options', 'correct', 'explanation']
                for field in required_fields:
                    if field not in q:
                        print(f"   ❌ 题目 {i} 缺少字段：{field}")
                        return False

                # 检查 correct 值是否有效
                correct_idx = q['correct']
                if isinstance(correct_idx, list):
                    if (not correct_idx or
                        any(not isinstance(idx, int) or idx < 0 or idx >= len(q['options']) for idx in correct_idx)):
                        print(f"   ❌ 题目 {i} 的 correct 值无效（应该是 0-{len(q['options'])-1} 的整数数组）")
                        return False
                elif not isinstance(correct_idx, int) or correct_idx < 0 or correct_idx >= len(q['options']):
                    print(f"   ❌ 题目 {i} 的 correct 值无效（应该是 0-{len(q['options'])-1}）")
                    return False

                print(f"   ✓ 题目 {i}: {q['question'][:30]}...")

            print()

        # 总结
        print("=" * 60)
        print(f"✅ 验证成功！")
        print(f"   总分类数：{len(categories)}")
        print(f"   总题目数：{total_questions}")
        print("=" * 60)
        print()
        print("分类列表：")
        for cat in categories:
            print(f"   • {cat}")

        print()
        print("✅ 现在可以用浏览器打开 index.html 开始做题了！")
        return True

    except json.JSONDecodeError as e:
        print(f"❌ JSON 格式错误：")
        print(f"   行 {e.lineno}, 列 {e.colno}")
        print(f"   {e.msg}")
        print()
        print("💡 提示：")
        print("   • 检查是否缺少或多余的逗号")
        print("   • 检查双引号是否配对")
        print("   • 检查花括号和方括号是否配对")
        return False

    except Exception as e:
        print(f"❌ 错误：{e}")
        return False

if __name__ == '__main__':
    # 如果指定了文件名，使用指定的文件
    filename = sys.argv[1] if len(sys.argv) > 1 else "questions.json"

    success = validate_quiz_json(filename)
    sys.exit(0 if success else 1)
