import requests
import time
import re
import os

SNORT_LOG = "/var/log/snort/alert"

print("🚀 Bridge init... waiting alert of Snort...")


def extract_ip(line):
    if "->" not in line:
        return None

    try:
        parts = line.split("}")
        if len(parts) < 2:
            return None

        traffic = parts[1].strip()

        src = traffic.split("->")[0].strip()

        # filtrar timestamps tipo 13:28:54
        if re.match(r'^\d{2}:\d{2}:\d{2}$', src):
            return None

        return src

    except:
        return None


# Esperar ficheiro existir
while not os.path.exists(SNORT_LOG):
    print("⏳ Esperando log do Snort...")
    time.sleep(2)

# 🔥 open  mode "tail -f"
with open(SNORT_LOG, "r") as f:
    f.seek(0, 2)  # vai para o fim do ficheiro

    while True:
        line = f.readline()

        if not line:
            time.sleep(1)
            continue

        ip = extract_ip(line)

        if not ip:
            continue

        print(f"[SNORT] IP detected: {ip}")

        # 🔹 Bloom Filter
        try:
            r = requests.post("http://bloom_filter:5000/check", json={"ip": ip}, timeout=2)
            exists = r.json().get("exists", False)
        except Exception as e:
            print(f"[ERRO BLOOM] {e}")
            continue

        if exists:
            print(f"[BLOOM] IP already checked: {ip}")

            # 🔹 ML
            try:
                ml = requests.post("http://ml_service:6000/predict", json={"ip": ip}, timeout=2)
                malicious = ml.json().get("malicious", False)
            except Exception as e:
                print(f"[ERRO ML] {e}")
                continue

            if malicious:
                print(f"[ALERT] 🚨  real Attack: {ip}")
            else:
                print(f"[FP REDUCED] ⚠️ False positive: {ip}")

        else:
            print(f"[NEW IP] 🆕 New IP: {ip}")