import platform
import socket
import json
import psutil
import requests
from datetime import datetime

API_ENDPOINT = "https://system-inventory-api.onrender.com/api/agent/report"

def get_system_info():
    try:
        system_data = {
            "agent_id": socket.getfqdn(),
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "cpu_cores": psutil.cpu_count(logical=False),
            "cpu_threads": psutil.cpu_count(logical=True),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "disk_total_gb": round(psutil.disk_usage('/').total / (1024**3), 2),
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "ip_address": get_ip_address(),
            "timestamp": datetime.now().isoformat()
        }
        return system_data
    except Exception as e:
        return {"error": str(e)}

def get_ip_address():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        # fallback if hostname resolution fails
        return requests.get("https://api.ipify.org").text

def send_report():
    system_data = get_system_info()
    headers = {'Content-Type': 'application/json'}

    response = requests.post(API_ENDPOINT, headers=headers, data=json.dumps(system_data))

    if response.status_code == 200:
        print(f"✅ Report sent successfully for agent: {system_data['agent_id']}")
    else:
        print(f"❌ Failed to send report. Status: {response.status_code}, Error: {response.text}")

if __name__ == "__main__":
    send_report()
