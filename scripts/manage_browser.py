import ctypes
from ctypes import wintypes
import time
import pyperclip
import sys

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

def init_desktop():
    hwinsta = user32.OpenWindowStationW('winsta0', False, 0x0000037F)
    user32.SetProcessWindowStation(hwinsta)
    hdesk = user32.OpenDesktopW('default', 0, False, 0x01FF)
    user32.SetThreadDesktop(hdesk)

def get_brave_hwnd():
    init_desktop()
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
        print("Brave window not found!")
        return False
    fore_hwnd = user32.GetForegroundWindow()
    fore_thread = user32.GetWindowThreadProcessId(fore_hwnd, None)
    app_thread = kernel32.GetCurrentThreadId()
    user32.AttachThreadInput(fore_thread, app_thread, True)
    user32.ShowWindow(hwnd, 3) # SW_SHOWMAXIMIZED
    user32.SwitchToThisWindow(hwnd, True)
    user32.BringWindowToTop(hwnd)
    user32.AttachThreadInput(fore_thread, app_thread, False)
    time.sleep(0.5)
    return True

def switch_to_tab(tab_number):
    activate_brave()
    # Press Ctrl + <tab_number>
    user32.keybd_event(0x11, 0, 0, 0) # CTRL down
    time.sleep(0.05)
    vk = ord(str(tab_number))
    user32.keybd_event(vk, 0, 0, 0) # key down
    time.sleep(0.05)
    user32.keybd_event(vk, 0, 2, 0) # key up
    user32.keybd_event(0x11, 0, 2, 0) # CTRL up
    time.sleep(1.0)
    print(f"Switched to tab {tab_number}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        tab = int(sys.argv[1])
        switch_to_tab(tab)
    else:
        activate_brave()

