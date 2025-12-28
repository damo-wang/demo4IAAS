from flask import Flask, request, jsonify
import os
import random

app = Flask(__name__)

NODE_NAME = os.getenv("NODE_NAME", "unknown-node")

@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "node": NODE_NAME,
        "cpu_usage": round(random.uniform(0.1, 0.9), 2),
        "mem_usage": round(random.uniform(0.1, 0.9), 2)
    })

@app.route("/exec", methods=["POST"])
def exec_cmd():
    data = request.get_json() or {}
    cmd = data.get("cmd", "")

    return jsonify({
        "node": NODE_NAME,
        "cmd": cmd,
        "result": f"simulated result of `{cmd}`",
        "status": "ok"
    })

@app.route("/", methods=["GET"])
def home():
    return jsonify({"msg": f"Node Agent running on {NODE_NAME}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
