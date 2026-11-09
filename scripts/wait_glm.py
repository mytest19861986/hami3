import time
import sys
import ctypes
from ctypes import wintypes
from PIL import ImageGrab

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

def init_desktop():
    hwinsta = user32.OpenWindowStationW('winsta0', False, 0x0000037F)
    user32.SetProcessWindowStation(hwinsta)
    hdesk = user32.OpenDesktopW('default', 0, False, 0x01FF)
    user32.SetThreadDesktop(hdesk)

def get_firefox_hwnd():
    init_desktop()
    firefox_hwnd = None
    def cb(hwnd, l):
        nonlocal firefox_hwnd
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buff = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buff, length + 1)
                if 'Firefox' in buff.value:
                    firefox_hwnd = hwnd
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)(cb), 0)
    return firefox_hwnd

def activate_firefox():
    hwnd = get_firefox_hwnd()
    if not hwnd:
        return False
    fore_hwnd = user32.GetForegroundWindow()
    fore_thread = user32.GetWindowThreadProcessId(fore_hwnd, None)
    app_thread = kernel32.GetCurrentThreadId()
    user32.AttachThreadInput(fore_thread, app_thread, True)
    user32.ShowWindow(hwnd, 9)
    user32.ShowWindow(hwnd, 3)
    user32.SwitchToThisWindow(hwnd, True)
    user32.BringWindowToTop(hwnd)
    user32.AttachThreadInput(fore_thread, app_thread, False)
    time.sleep(0.3)
    return True

def is_glm_generating():
    activate_firefox()
    im = ImageGrab.grab()
    
    # Check stop button (black circle 589..618, 910..939 with white square 598..611, 918..931)
    white_square = 0
    for y in range(918, 931):
        for x in range(598, 611):
            r, g, b = im.getpixel((x, y))[:3]
            if r > 240 and g > 240 and b > 240:
                white_square += 1
                
    dark_circle = 0
    for y in range(910, 939):
        for x in range(589, 618):
            r, g, b = im.getpixel((x, y))[:3]
            if r < 30 and g < 30 and b < 30:
                dark_circle += 1
                
    generating = (white_square > 50 and dark_circle > 100)
    return generating, im, white_square, dark_circle

def wait_for_completion(max_seconds=120):
    print("Monitoring GLM...")
    consecutive_stopped = 0
    start = time.time()
    
    while time.time() - start < max_seconds:
        gen, im, ws, dc = is_glm_generating()
        if gen:
            consecutive_stopped = 0
            print(f"Generating (ws={ws}, dc={dc})...")
        else:
            consecutive_stopped += 1
            print(f"Stopped candidate {consecutive_stopped} (ws={ws}, dc={dc})")
            if consecutive_stopped >= 2: # verified stable for 2 checks
                print(">>> GLM HAS DEFINITIVELY STOPPED <<<")
                im.save(r'C:\Users\IT\.gemini\antigravity\brain\7cae2d48-3747-4722-9e99-34a9e33eaa04\scratch\firefox_completed.png')
                return True
        time.sleep(4)
        
    print(">>> TIMEOUT REACHED <<<")
    return False

if __name__ == '__main__':
    wait_for_completion(90)
