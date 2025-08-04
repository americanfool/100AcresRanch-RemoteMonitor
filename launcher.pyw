#!/usr/bin/env pythonw
"""
Silent launcher for Heartbeat Monitor
Runs without showing command prompt window
"""

import subprocess
import sys
import os

def main():
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Change to the script directory
    os.chdir(script_dir)
    
    try:
        # Install dependencies silently
        print("Installing dependencies...")
        subprocess.run([sys.executable, "-m", "pip", "install", "ping3", "matplotlib", "paramiko"], 
                      capture_output=True, check=True)
        
        # Run the heartbeat monitor
        print("Starting Heartbeat Monitor...")
        subprocess.run([sys.executable, "heartbeat_monitor.py"], check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        input("Press Enter to exit...")
    except Exception as e:
        print(f"Unexpected error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main() 