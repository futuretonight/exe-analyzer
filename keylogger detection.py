import keyboard

def detect_keylogger():
    print("Monitoring for keyloggers...")
    while True:
        event = keyboard.read_event()
        if event.event_type == keyboard.KEY_DOWN:
            print(f"[KEYLOGGER DETECTED] {event.name}")

if __name__ == "__main__":
    detect_keylogger()
