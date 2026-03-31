#!/usr/bin/env python3
"""
PathFinder — Local Server Launcher
Serves the web UI over http://localhost so all AI providers work correctly.

Usage:
    python serve.py          # serves on http://localhost:8080
    python serve.py 3000     # custom port
"""
import sys
import os
import webbrowser
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.join(os.path.dirname(__file__), 'web'), **kwargs)
    def log_message(self, format, *args):
        pass  # suppress request logs for cleaner output

def open_browser():
    import time; time.sleep(0.4)
    webbrowser.open(f'http://localhost:{PORT}')

print(f"""
  ██████╗  █████╗ ████████╗██╗  ██╗███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
  ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
  ██████╔╝███████║   ██║   ███████║█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
  ██╔═══╝ ██╔══██║   ██║   ██╔══██║██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
  ██║     ██║  ██║   ██║   ██║  ██║██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
  ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝

  Attack Path Simulator — Local Server
  ─────────────────────────────────────────────────────────────────────
  Serving at:  http://localhost:{PORT}
  Opening browser automatically...

  Press Ctrl+C to stop.
""")

threading.Thread(target=open_browser, daemon=True).start()
try:
    HTTPServer(('', PORT), Handler).serve_forever()
except KeyboardInterrupt:
    print("\n  Server stopped.")
