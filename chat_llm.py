# chat_llm.py
from openai import OpenAI
import os

# 替换成你自己的 Key 和 URL（如果你用通义千问的兼容 OpenAPI 接口）
client = OpenAI(
    api_key="sk-ad7c4d4291bf485bb5d4630cc7633f4b",  # 替换为你的 key
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"  # 通义千问 OpenAPI 模式 URL
)

def call_qwen_chat(messages):
    """
    messages: List[Dict] like:
        [{"role": "user", "content": "你好"},
         {"role": "assistant", "content": "你好，有什么可以帮您？"},
         {"role": "user", "content": "你能告诉我今天的新闻吗？"}]
    """
    try:
        response = client.chat.completions.create(
            model="qwen-plus",  # 替换为你的模型名称，如通义为 qwen-plus、qwen-turbo 等
            messages=messages,
            temperature=0.7,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"【机器人出错】{str(e)}"