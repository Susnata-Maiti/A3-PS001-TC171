import time
import os
import sys
import frida

# Globals to track metrics
event_timestamps = []
THRESHOLD = 10           # Max renames allowed...
TIME_WINDOW = 2.0        # ...within this many seconds
first_rename_time = 0.0

def evaluate_behavior(payload):
    global event_timestamps, first_rename_time

    current_time = time.time()

    # Start the timer on the very first malicious-looking rename
    if len(event_timestamps) == 0:
        first_rename_time = current_time

    event_timestamps.append(current_time)

    # Clean up old events outside the time window
    event_timestamps = [t for t in event_timestamps if current_time - t <= TIME_WINDOW]

    # If the threshold is breached, calculate metrics and execute kill-switch
    if len(event_timestamps) >= THRESHOLD:
        kill_time = time.time()
        measured_delay = kill_time - first_rename_time
        files_changed = len(event_timestamps)

        print("\n[!!!] RANSOMWARE BEHAVIOR DETECTED [!!!]")
        print("-" * 40)
        print(f"Metrics Report:")
        print(f" > Measured Delay : {measured_delay:.3f} seconds")
        print(f" > Files Changed  : {files_changed} files")
        print("-" * 40)

        # Fire kill-switch safely
        # Fallback to hardcoded package if the JS hook payload lacks the key
        target_pkg = payload.get('package_name', 'com.redteam.simulator') if isinstance(payload, dict) else 'com.redteam.simulator'
        os.system(f"adb shell am force-stop {target_pkg}")
        print("[+] Threat neutralized. Engine exiting.\n")
        os._exit(0)

def on_message(message, data):
    if message['type'] == 'send':
        evaluate_behavior(message['payload'])
    elif message['type'] == 'error':
        print(f"[!] Frida Error: {message['description']}")

if __name__ == "__main__":
    try:
        # 1. Connect to the emulator
        device = frida.get_usb_device()

        # 2. Attach using the exact internal package name
        session = device.attach("RedTeam Simulator")

        # 3. Load the hook script
        with open("ueba_hook.js", "r") as f:
            script = session.create_script(f.read())

        # 4. Bind the message handler to your Python function
        script.on("message", on_message)
        script.load()

        print("[*] Engine Active. Waiting for events...")
        sys.stdin.read()

    except frida.ProcessNotFoundError:
        print("[!] Error: Could not find 'com.redteam.simulator'.")
        print("[!] FIX: Make sure the Red Team Simulator app is OPEN and visible on the emulator screen before running this script.")
    except FileNotFoundError:
        print("[!] Error: 'ueba_hook.js' not found. Ensure both files are in the exact same directory.")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
