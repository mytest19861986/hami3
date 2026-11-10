import pyperclip

with open('docs/COMMANDER_STATUS_006.md', 'r', encoding='utf-8') as f:
    content = f.read()

pyperclip.copy(content)
print("SUCCESS: Copied docs/COMMANDER_STATUS_006.md to Windows Clipboard!")
