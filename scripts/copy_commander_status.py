import pyperclip
from pathlib import Path

status_file = Path(__file__).resolve().parent.parent / "docs" / "COMMANDER_STATUS_008.md"
content = status_file.read_text(encoding="utf-8")
pyperclip.copy(content)
print(f"Successfully copied {status_file.name} ({len(content)} characters) to clipboard!")
