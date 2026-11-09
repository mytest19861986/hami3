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

def is_stop_button_present(im):
    # Scan the y-band 910..940 across x 550..1100 for the stop button circle
    dark_pixels = []
    for y in range(910, 940):
        for x in range(550, 1100):
            r, g, b = im.getpixel((x, y))[:3]
            if r < 30 and g < 30 and b < 30:
                dark_pixels.append((x, y))
                
    if len(dark_pixels) > 300:
        # Candidate circle found
        min_x, max_x = min(p[0] for p in dark_pixels), max(p[0] for p in dark_pixels)
        min_y, max_y = min(p[1] for p in dark_pixels), max(p[1] for p in dark_pixels)
        cx = (min_x + max_x) // 2
        cy = (min_y + max_y) // 2
        
        # Check white square in center
        ws = 0
        for y in range(cy - 6, cy + 7):
            for x in range(cx - 6, cx + 7):
                r, g, b = im.getpixel((x, y))[:3]
                if r > 230 and g > 230 and b > 230:
                    ws += 1
        if ws > 50:
            return True, cx, cy, ws
    return False, 0, 0, 0

def check_status():
    activate_firefox()
    im = ImageGrab.grab()
    im.save(r'C:\Users\IT\.gemini\antigravity\brain\7cae2d48-3747-4722-9e99-34a9e33eaa04\scratch\firefox_state.png')
    generating, cx, cy, ws = is_stop_button_present(im)
    print(f"GENERATING: {generating} (at {cx},{cy} with {ws} white pixels)")
    return generating

def wait_until_stopped(timeout=90):
    print("Waiting until GLM stops...")
    consecutive_stopped = 0
    start = time.time()
    while time.time() - start < timeout:
        activate_firefox()
        im = ImageGrab.grab()
        generating, cx, cy, ws = is_stop_button_present(im)
        if generating:
            consecutive_stopped = 0
            print(f"GLM generating (btn at {cx},{cy})...")
        else:
            consecutive_stopped += 1
            print(f"Stop detected count={consecutive_stopped}")
            if consecutive_stopped >= 2:
                im.save(r'C:\Users\IT\.gemini\antigravity\brain\7cae2d48-3747-4722-9e99-34a9e33eaa04\scratch\firefox_final.png')
                print(">>> GLM FULLY STOPPED <<<")
                return True
        time.sleep(4)
    print(">>> TIMEOUT <<<")
    return False

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'wait':
        wait_until_stopped(90)
    else:
        check_status()
