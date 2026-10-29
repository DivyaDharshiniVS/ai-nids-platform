import subprocess
import re
import sys
import time

print("Starting cloudflared tunnel to http://localhost:8501...", flush=True)

proc = subprocess.Popen(
    [r".\cloudflared.exe", "tunnel", "--url", "http://localhost:8501"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
)

url_found = None
url_regex = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")

log_active = open("cf_active.log", "w", encoding="utf-8")
log_active_alt = open("active_cf.log", "w", encoding="utf-8")

for line in iter(proc.stdout.readline, ''):
    line_clean = line.strip()
    if line_clean:
        print(line_clean, flush=True)
        log_active.write(line_clean + "\n")
        log_active.flush()
        log_active_alt.write(line_clean + "\n")
        log_active_alt.flush()
    if not url_found:
        match = url_regex.search(line_clean)
        if match:
            url_found = match.group(0)
            print(f"\n==========================================", flush=True)
            print(f"ACTIVE_CLOUDFLARE_URL: {url_found}", flush=True)
            print(f"==========================================\n", flush=True)
            with open("tunnel_url.txt", "w", encoding="utf-8") as f:
                f.write(url_found)

proc.wait()
log_active.close()
log_active_alt.close()
