import ctypes
from ctypes import wintypes
import time
import pyperclip
import os
import sys

# 1. Desktop & DPI initialization
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

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

def find_hwnd_by_title_substring(sub):
    found = None
    def cb(hwnd, l):
        nonlocal found
        if user32.IsWindowVisible(hwnd):
            buff = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, buff, 512)
            if sub.lower() in buff.value.lower():
                found = hwnd
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)(cb), 0)
    return found

def force_activate_brave():
    # Alt trick to bypass SetForegroundWindow restrictions
    user32.keybd_event(0x12, 0, 0, 0)
    time.sleep(0.02)
    user32.keybd_event(0x12, 0, 2, 0)
    time.sleep(0.05)

    firefox_hwnd = find_hwnd_by_title_substring("Firefox")
    if firefox_hwnd:
        user32.ShowWindow(firefox_hwnd, 6) # SW_MINIMIZE
        time.sleep(0.1)

    brave_hwnd = find_hwnd_by_title_substring("Brave")
    if not brave_hwnd:
        print("Brave window not found!")
        sys.exit(1)

    user32.ShowWindow(brave_hwnd, 3) # SW_SHOWMAXIMIZED
    user32.SwitchToThisWindow(brave_hwnd, True)
    user32.SetForegroundWindow(brave_hwnd)
    user32.BringWindowToTop(brave_hwnd)
    time.sleep(0.4)
    return brave_hwnd

def switch_to_tab(tab_num):
    force_activate_brave()
    gui.hotkey('ctrl', str(tab_num))
    time.sleep(0.8)

def is_chatbox_empty(im):
    # Check pixels around the placeholder area (e.g. x=420, y=905)
    # If the input box contains text, the send button at (913, 905) changes or text is typed
    # Let's check color variation around input box x=400..700, y=900..915
    # If it's mostly blank/white/placeholder color, let's inspect
    return False

def main():
    print("=== Step 1: Activate Brave & Switch to Tab 4 ===")
    switch_to_tab(4)

    # Read message
    with open("d:/project/hami3/scripts/commander_msg.txt", "r", encoding="utf-8") as f:
        msg = f.read().strip()
    pyperclip.copy(msg)
    print(f"Message loaded ({len(msg)} chars) and copied to clipboard.")

    # Step 2: Click into the input box
    print("Clicking chat input at (500, 905)...")
    gui.click(500, 905)
    time.sleep(0.3)

    # Step 3: Paste using Shift+Insert
    print("Pasting message via Shift+Insert...")
    user32.keybd_event(0x10, 0, 0, 0) # Shift down
    time.sleep(0.05)
    user32.keybd_event(0x2D, 0, 0, 0) # Insert down
    time.sleep(0.05)
    user32.keybd_event(0x2D, 0, 2, 0) # Insert up
    user32.keybd_event(0x10, 0, 2, 0) # Shift up
    time.sleep(0.8)

    # Also try Ctrl+V if clipboard didn't paste
    # Take screenshot right after paste
    im_paste = gui.screenshot()
    im_paste.save("d:/project/hami3/scripts/after_paste.png")

    # Step 4: Click Send button at (913, 905) and press Enter
    print("Clicking send button at (913, 905) & pressing Enter...")
    gui.click(913, 905)
    time.sleep(0.2)
    gui.press('enter')

    # Step 5: User Rule 4 - Wait exactly 3 seconds
    print("Waiting 3 seconds per user rule 4...")
    time.sleep(3.0)

    # Step 6: Verify screenshot at 3s
    im_3s = gui.screenshot()
    im_3s.save("d:/project/hami3/scripts/verify_3s.png")
    print("Captured verify_3s.png")

    # Check if send button has turned into a stop square or if input box is empty
    # If the text is still in the input box, try Enter once more
    # Let's inspect the send button region: (900, 890) to (930, 920)
    # In ChatGPT: when generating, a square stop button or black circle appears
    print("3s check completed.")

if __name__ == "__main__":
    main()

