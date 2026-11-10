import pyperclip

with open('docs/reviews/glm_review_pass2_prompt.md', 'r', encoding='utf-8') as f:
    content = f.read()

pyperclip.copy(content)
print("SUCCESS: Copied GLM Pass 2 prompt to Windows Clipboard!")
