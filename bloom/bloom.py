from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)

SIZE = 1_000_000
HASH_COUNT = 7
bloom = [0] * SIZE

def hash_item(item, i):
    return int(hashlib.sha256((item + str(i)).encode()).hexdigest(), 16) % SIZE

def insert(item):
    for i in range(HASH_COUNT):
        bloom[hash_item(item, i)] += 1

def query(item):
    return all(bloom[hash_item(item, i)] > 0 for i in range(HASH_COUNT))

@app.route("/check", methods=["POST"])
def check():
    ip = request.json["ip"]
    exists = query(ip)
    if not exists:
        insert(ip)
    return jsonify({"exists": exists})

app.run(host="0.0.0.0", port=5000)