import ctypes
from ctypes import wintypes
import time
import pyperclip
import os
import sys

user32 = ctypes.windll.user32
try:
    user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
except Exception:
    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass

hwinsta = user32.OpenWindowStationW("winsta0", False, 0x0000037F)
if hwinsta:
    user32.SetProcessWindowStation(hwinsta)
hdesk = user32.OpenDesktopW("default", 0, False, 0x01FF)
if hdesk:
    user32.SetThreadDesktop(hdesk)

import pyautogui as gui
gui.FAILSAFE = False

def find_brave():
    brave_hwnd = None
    def cb(hwnd, l):
        nonlocal brave_hwnd
        if user32.IsWindowVisible(hwnd):
            buff = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, buff, 512)
            if "Brave" in buff.value:
                brave_hwnd = hwnd
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)(cb), 0)
    return brave_hwnd

def activate_tab(tab_num=6):
    user32.keybd_event(0x12, 0, 0, 0)
    time.sleep(0.02)
    user32.keybd_event(0x12, 0, 2, 0)
    time.sleep(0.05)

    brave = find_brave()
    if not brave:
        print("ERROR: Brave not found")
        sys.exit(1)
    user32.ShowWindow(brave, 3)
    user32.SwitchToThisWindow(brave, True)
    user32.SetForegroundWindow(brave)
    user32.BringWindowToTop(brave)
    time.sleep(0.3)

    gui.hotkey('ctrl', str(tab_num))
    time.sleep(0.8)

def send_packet():
    activate_tab(6)
    with open("d:/project/hami3/scripts/glm_audit_packet.txt", "r", encoding="utf-8") as f:
        msg = f.read().strip()
    pyperclip.copy(msg)
    print(f"Loaded packet ({len(msg)} chars) and copied to clipboard.")

    # Click input box at (450, 835)
    print("Clicking input box at (450, 835)...")
    gui.click(450, 835)
    time.sleep(0.3)

    # Paste
    print("Pasting via Shift+Insert...")
    user32.keybd_event(0x10, 0, 0, 0)
    time.sleep(0.05)
    user32.keybd_event(0x2D, 0, 0, 0)
    time.sleep(0.05)
    user32.keybd_event(0x2D, 0, 2, 0)
    user32.keybd_event(0x10, 0, 2, 0)
    time.sleep(0.8)

    # Click send button at (1115, 913) and press Enter
    print("Clicking send button at (1115, 913)...")
    gui.click(1115, 913)
    time.sleep(0.2)
    gui.press('enter')

    # Rule 4: Wait 3 seconds
    print("Waiting 3 seconds per rule 4...")
    time.sleep(3.0)

    # Capture 3s verification
    pic = gui.screenshot()
    os.makedirs("d:/project/hami3/scripts", exist_ok=True)
    pic.save("d:/project/hami3/scripts/glm_audit_3s_verify.png")
    print("Verification screenshot saved to scripts/glm_audit_3s_verify.png")

if __name__ == "__main__":
    send_packet()

