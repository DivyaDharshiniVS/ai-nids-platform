import socket
import threading
import urllib.request
import json
import time

TARGET_SUBDOMAIN = "smart-tourism-planning"
LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 8501
POOL_SIZE = 10

def forward(src, dst):
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass

def bridge_connection(remote_host, remote_port):
    remote_sock = None
    local_sock = None
    try:
        remote_sock = socket.create_connection((remote_host, remote_port))
        local_sock = socket.create_connection((LOCAL_HOST, LOCAL_PORT))

        t1 = threading.Thread(target=forward, args=(remote_sock, local_sock), daemon=True)
        t2 = threading.Thread(target=forward, args=(local_sock, remote_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception:
        pass
    finally:
        if remote_sock:
            try:
                remote_sock.close()
            except Exception:
                pass
        if local_sock:
            try:
                local_sock.close()
            except Exception:
                pass

def worker(remote_host, remote_port):
    while True:
        try:
            bridge_connection(remote_host, remote_port)
        except Exception:
            pass
        time.sleep(0.05)

def main():
    url = f"https://localtunnel.me/{TARGET_SUBDOMAIN}?new"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'localtunnel-client/1.0'})
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())
        url_assigned = data['url']
        remote_port = data["port"]
        msg = f"TUNNEL_READY: {url_assigned} on remote port {remote_port}"
        print(msg, flush=True)
        with open("tunnel_out.log", "w", encoding="utf-8") as f_out:
            f_out.write(msg + "\n")
        with open("fixed_tunnel.log", "w", encoding="utf-8") as f_fix:
            f_fix.write(msg + "\n")
        with open("tunnel_url.txt", "w", encoding="utf-8") as f:
            f.write(url_assigned)
    except Exception as e:
        err_msg = f"TUNNEL_REGISTRATION_ERROR: {e}"
        print(err_msg, flush=True)
        with open("tunnel_err.log", "w", encoding="utf-8") as f_err:
            f_err.write(err_msg + "\n")
        return

    remote_host = "localtunnel.me"
    for _ in range(POOL_SIZE):
        t = threading.Thread(target=worker, args=(remote_host, remote_port), daemon=True)
        t.start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
