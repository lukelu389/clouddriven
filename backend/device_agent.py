import time, shutil, requests

API = "http://127.0.0.1:8000"
DEVICE_TOKEN = "<eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsImVtYWlsIjoidGVzdDFAZXhhbXBsZS5jb20iLCJleHAiOjE3NjA5NzMzODV9.VWgOIQdcVmJ0xNK1Wj0Nc7l5PURXbD3uWTYVxOV28KM>"

def stats():
    du = shutil.disk_usage("/")
    return {"total_bytes": du.total, "free_bytes": du.free, "used_bytes": du.total - du.free}

HEADERS = {"Authorization": f"Bearer {DEVICE_TOKEN}"}

while True:
    try:
        r = requests.post(f"{API}/api/agent/heartbeat", json=stats(), headers=HEADERS, timeout=10)
        print("Heartbeat:", r.json())
    except Exception as e:
        print("Heartbeat failed:", e)
    time.sleep(30)
