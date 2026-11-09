import ctypes
from ctypes import wintypes
import time
import pyperclip
import os

if os.name == "nt":
    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except Exception:
        ctypes.windll.user32.SetProcessDPIAware()
    try:
        hwinsta = ctypes.windll.user32.OpenWindowStationW("winsta0", False, 0x0000037F)
        if hwinsta:
            ctypes.windll.user32.SetProcessWindowStation(hwinsta)
        hdesk = ctypes.windll.user32.OpenDesktopW("default", 0, False, 0x01FF)
        if hdesk:
            ctypes.windll.user32.SetThreadDesktop(hdesk)
    except Exception:
        pass

import pyautogui as gui
gui.FAILSAFE = False

user32 = ctypes.windll.user32

# 1. Close any context menu with Escape
user32.keybd_event(0x1B, 0, 0, 0)
time.sleep(0.05)
user32.keybd_event(0x1B, 0, 2, 0)
time.sleep(0.2)

# 2. Read message and copy to clipboard
with open("d:/project/hami3/scripts/commander_msg.txt", "r", encoding="utf-8") as f:
    msg = f.read()

pyperclip.copy(msg)
print("Copied message to clipboard, length:", len(msg))

# 3. Focus input box
gui.click(420, 905)
time.sleep(0.3)

# 4. Paste with Shift+Insert
gui.hotkey('shift', 'insert')
time.sleep(0.8)

# 5. Click Send button at x=915, y=905
gui.click(915, 905)
time.sleep(0.2)
gui.press('enter')
print("Send clicked and Enter pressed.")

# 6. User Rule: Wait 3 seconds
print("Waiting 3 seconds to check chatbox...")
time.sleep(3.0)

# 7. Capture verification screenshot
pic = gui.screenshot()
os.makedirs("d:/project/hami3/scripts", exist_ok=True)
pic.save("d:/project/hami3/scripts/commander_sent.png")
print("Saved verification screenshot to scripts/commander_sent.png")

