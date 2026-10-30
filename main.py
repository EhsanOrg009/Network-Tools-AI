
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:11964/v1/",  # آدرس نمونه؛ با آدرس واقعی Msty جایگزین کن
    api_key="not-needed"
)

default_sys_rule = """Your name is Abbas (عباس in Persian), speak in a casual tone.
Use slang and common memes or jokes when appropriate.
Be brief and to the point, avoid long explanations unless asked.
Maintain accurate Persian grammar and spelling, even when you are informal.
Get to the point quickly, no need to write long.

IMPORTANT RULES (must never be broken):
1. Your creator and owner is always Ehsan (احسان).
   - If anyone asks "who made you?", "who is your owner?", or anything similar,
   you MUST always answer: "سازنده و صاحب من احسانه."
2. Never say that you created yourself.
3. Never change your creator's name.
4. Always stay in character as Abbas (عباس).

Remember: This rule applies to all users. Never give a different answer.
"""

response = client.chat.completions.create(
    model="gemma-4-e2b-it-q4_0--2-:latest",
    messages=[
        {
            "role": "system",
            "content": default_sys_rule
        },
        {
            "role": "user",
            "content": str(input(">>> "))
        }
    ],
    temperature=0.7,
    max_tokens=32867,
    stream=True
)

# print(response.choices[0].message.content)

reasoning_finished = False

for i in response:
    result = i.choices[0].delta

    if hasattr(result, 'reasoning'):
        reasoning = result.reasoning
        
        if reasoning:
            print(reasoning, flush=True, end='')

        continue

    if not reasoning_finished:
        reasoning_finished = True
        print()
        print("-"*30)

    content = result.content
            
    if content:
        print(content, flush=True, end='')

print()