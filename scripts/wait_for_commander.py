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

def check_one_cycle(cycle_num):
    activate_brave()
    time.sleep(0.5)
    pic = gui.screenshot()
    out_path = f"d:/project/hami3/scripts/commander_poll_{cycle_num:02d}.png"
    pic.save(out_path)
    latest_path = "d:/project/hami3/scripts/commander_poll_latest.png"
    pic.save(latest_path)
    print(f"Cycle {cycle_num}: screenshot saved to {out_path}")
    return latest_path

def main():
    max_cycles = 20 # 20 * 30s = 600s = 10 minutes
    print("Starting monitoring loop for Commander response (up to 10 min, checking every 30s)...")
    
    for i in range(1, max_cycles + 1):
        print(f"\n--- Checking cycle {i}/{max_cycles} (elapsed: {(i-1)*30}s) ---")
        check_one_cycle(i)
        
        # Check if complete will be inspected or sleep 30 seconds
        if i < max_cycles:
            print("Waiting 30 seconds before next check...")
            time.sleep(30.0)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "once":
        cycle = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        check_one_cycle(cycle)
    else:
        main()

