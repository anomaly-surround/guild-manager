"""Exports icon.svg as the app icons for installing Guild Manager to a home screen / desktop.

- icon-180.png         apple-touch-icon (iOS masks corners itself -> square, full-bleed)
- icon-192/512.png     manifest icons (full-bleed; the shield sits inside the maskable safe zone)

The browser tab keeps using icon.svg directly.

PNGs are rendered with headless Chrome. Run: python export_app_icons.py
"""
import base64
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
OUT = HERE.parent
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
MARK = HERE.parent / "icon.svg"


def render_png(svg, size, dest):
    # Page goes in as a data: URL - headless Chrome can't read file:// pages from %TEMP% here.
    html = ("<!doctype html><html><head><style>html,body{margin:0;background:transparent}"
            f"svg{{display:block;width:{size}px;height:{size}px}}</style></head>"
            f"<body>{svg}</body></html>")
    url = "data:text/html;base64," + base64.b64encode(html.encode("utf-8")).decode("ascii")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                        "--default-background-color=00000000", f"--user-data-dir={tmp}",
                        f"--window-size={size},{size}", f"--screenshot={dest}", url],
                       check=True, capture_output=True, timeout=60)


def main():
    rounded = MARK.read_text(encoding="utf-8")
    full_bleed = rounded.replace('rx="16"', 'rx="0"', 1)
    for size in (180, 192, 512):
        render_png(full_bleed, size, OUT / f"icon-{size}.png")
    print("wrote icon-180.png, icon-192.png, icon-512.png to", OUT)


if __name__ == "__main__":
    main()
