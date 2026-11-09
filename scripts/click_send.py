import time
import sys
import ctypes
from PIL import ImageGrab

sys.path.append(r'D:\project\hami3\scripts')
import manage_firefox

user32 = ctypes.windll.user32

def send():
    manage_firefox.activate_firefox()
    time.sleep(0.5)
    
    # 1. Click at (797, 902)
    print("Clicking send button at (797, 902)...")
    user32.SetCursorPos(797, 902)
    time.sleep(0.15)
    user32.mouse_event(0x0002, 0, 0, 0, 0)
    time.sleep(0.1)
    user32.mouse_event(0x0004, 0, 0, 0, 0)
    time.sleep(0.5)
    
    # Check if that worked, or if we should press Ctrl+Enter / Enter
    im = ImageGrab.grab()
    im.save(r'C:\Users\IT\.gemini\antigravity\brain\7cae2d48-3747-4722-9e99-34a9e33eaa04\scratch\check_send.png')
    
    # Check if stop button is now present (meaning it submitted and started generating!)
    generating, cx, cy, ws = manage_firefox.is_stop_button_present(im)
    print(f"Generating after click: {generating}")
    
    if not generating:
        print("Trying Enter key...")
        # Click text area first to be focused
        user32.SetCursorPos(400, 850)
        time.sleep(0.1)
        user32.mouse_event(0x0002, 0, 0, 0, 0)
        time.sleep(0.05)
        user32.mouse_event(0x0004, 0, 0, 0, 0)
        time.sleep(0.2)
        
        user32.keybd_event(0x0D, 0, 0, 0) # ENTER
        time.sleep(0.05)
        user32.keybd_event(0x0D, 0, 2, 0)
        time.sleep(1.0)
        
        im2 = ImageGrab.grab()
        im2.save(r'C:\Users\IT\.gemini\antigravity\brain\7cae2d48-3747-4722-9e99-34a9e33eaa04\scratch\check_send2.png')
        gen2, cx2, cy2, ws2 = manage_firefox.is_stop_button_present(im2)
        print(f"Generating after Enter: {gen2}")

if __name__ == '__main__':
    send()
