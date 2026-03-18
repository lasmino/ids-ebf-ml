from flask import Flask, request, jsonify
import ipaddress

app = Flask(__name__)

# 🔥 Modelo ML (simulated robust)
def predict(ip):
    try:
        # suport IPv4 e IPv6
        ip_obj = ipaddress.ip_address(ip)

        # transformar IP em número
        score = int(ip_obj) % 100

        return score > 60  # ataque se score alto

    except Exception as e:
        print(f"[ERRO ML] IP inválido: {ip} | {e}")
        return False


@app.route("/predict", methods=["POST"])
def predict_api():
    data = request.get_json()

    if not data or "ip" not in data:
        return jsonify({"error": "IP not allowed"}), 400

    ip = data["ip"]

    result = predict(ip)

    return jsonify({"malicious": result})


if __name__ == "__main__":
    print("🚀 ML Service init on port 6000...")
    app.run(host="0.0.0.0", port=6000)