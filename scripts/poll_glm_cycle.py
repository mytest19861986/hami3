import ctypes
from ctypes import wintypes
import time
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
from PIL import Image
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

def activate_brave():
    user32.keybd_event(0x12, 0, 0, 0)
    time.sleep(0.02)
    user32.keybd_event(0x12, 0, 2, 0)
    time.sleep(0.05)
    brave = find_brave()
    if brave:
        user32.ShowWindow(brave, 3)
        user32.SwitchToThisWindow(brave, True)
        user32.SetForegroundWindow(brave)
        user32.BringWindowToTop(brave)

def check_glm(cycle=1):
    activate_brave()
    time.sleep(0.3)
    pic = gui.screenshot()
    path = f"d:/project/hami3/scripts/glm_poll_{cycle:02d}.png"
    pic.save(path)
    print(f"Cycle {cycle} screenshot saved to {path}")

if __name__ == "__main__":
    c = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    check_glm(c)

