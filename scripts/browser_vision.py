import ctypes
from ctypes import wintypes
import time
import os
import pyperclip
from PIL import Image

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
kernel32 = ctypes.windll.kernel32

def capture_screen(save_path="scripts/screen.png"):
    pic = gui.screenshot()
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    pic.save(save_path)
    print(f"Captured screen {pic.size} saved to {save_path}")
    return pic

def get_brave_hwnd():
    brave_hwnd = None
    def cb(hwnd, l):
        nonlocal brave_hwnd
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buff = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buff, length + 1)
                if 'Brave' in buff.value:
                    brave_hwnd = hwnd
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)(cb), 0)
    return brave_hwnd

def activate_brave():
    hwnd = get_brave_hwnd()
    if not hwnd:
        print("Brave window not found! Trying to click taskbar icon...")
        gui.click(730, 980)
        time.sleep(1.0)
        hwnd = get_brave_hwnd()
    if hwnd:
        fore_hwnd = user32.GetForegroundWindow()
        fore_thread = user32.GetWindowThreadProcessId(fore_hwnd, None)
        app_thread = kernel32.GetCurrentThreadId()
        user32.AttachThreadInput(fore_thread, app_thread, True)
        user32.ShowWindow(hwnd, 3) # SW_SHOWMAXIMIZED
        user32.SwitchToThisWindow(hwnd, True)
        user32.BringWindowToTop(hwnd)
        user32.AttachThreadInput(fore_thread, app_thread, False)
        time.sleep(0.5)
        print(f"Activated Brave window: {hwnd}")
        return True
    return False

def switch_tab(tab_num):
    activate_brave()
    # Click on the tab coordinate or use Ctrl+N
    tab_coords = {
        1: (65, 18),
        2: (165, 18),
        3: (265, 18),
        4: (375, 18), # ChatGPT hami3
        5: (500, 18), # Qwen
        6: (640, 18), # GLM (Z.ai)
        7: (770, 18), # Gemini
    }
    if tab_num in tab_coords:
        x, y = tab_coords[tab_num]
        gui.click(x, y)
        time.sleep(0.5)
    gui.hotkey('ctrl', str(tab_num))
    time.sleep(1.0)
    print(f"Switched to tab {tab_num}")

def send_chat_message(tab_num, input_x, input_y, send_x, send_y, message_text):
    switch_tab(tab_num)
    time.sleep(0.5)
    pyperclip.copy(message_text)
    
    # Click in input box
    gui.click(input_x, input_y)
    time.sleep(0.3)
    
    # Select all and paste
    gui.hotkey('ctrl', 'a')
    time.sleep(0.1)
    gui.press('backspace')
    time.sleep(0.1)
    gui.hotkey('ctrl', 'v')
    time.sleep(0.5)
    
    # Click send button
    gui.click(send_x, send_y)
    time.sleep(0.2)
    gui.press('enter')
    
    # User Rule: Wait 3 seconds
    print("Waiting 3 seconds to check chatbox...")
    time.sleep(3.0)
    
    # Capture verification screenshot
    capture_screen(f"scripts/verify_tab_{tab_num}.png")
    print(f"Message sent to tab {tab_num} and 3s verification captured.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "capture":
        capture_screen()
    elif len(sys.argv) > 1 and sys.argv[1] == "tab":
        switch_tab(int(sys.argv[2]))
        capture_screen(f"scripts/tab_{sys.argv[2]}.png")

