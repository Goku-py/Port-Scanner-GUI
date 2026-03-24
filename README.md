# Network Port Scanner GUI

Fast, lightweight, and fun TCP port scanner with a clean Tkinter interface.

## Why you'll like it

- 🎯 Simple UI: target + port range, then scan
- ⚡ Fast worker-pool scanning for better performance on larger ranges
- 🧠 Auto-labels common services (HTTP, HTTPS, SSH, MySQL, RDP, etc.)
- 📈 Live progress bar + elapsed time
- 🛑 Stop scan anytime
- 💾 Save open-port results to `.txt`
- 🖥️ Works on Windows, Linux, and macOS
- 📦 Zero third-party dependencies

## Screenshot

<img width="726" height="552" alt="image" src="https://github.com/user-attachments/assets/26b88b72-b3b0-4ab0-9e8c-ec25aafa70d3" />


## Quick start

```bash
python portscanergui.py
```

1. Enter a target IP/hostname (example: `192.168.29.1`)
2. Set start/end ports (default: `1` to `1024`)
3. Click **Start Scan**
4. Optionally click **Stop**
5. Save discovered open ports when done

## Requirements

- Python 3.7+
- Tkinter (usually included with Python)

## Safety note

Scan only systems you own or have explicit permission to test.
