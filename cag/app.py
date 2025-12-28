from flask import Flask, request, jsonify
import requests
import jwt
import datetime

app = Flask(__name__)

SECRET_KEY = "super-secret-demo-key"  # 必须与 CAM 相同

NODE_MAP = {
    "node-1": "http://node-1:8080",
    "node-2": "http://node-2:8080"
}

def verify_token():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, "missing_or_invalid_token_header"

    token = auth_header.replace("Bearer ", "")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload, None
    except Exception as e:
        return None, str(e)


@app.route("/nodes/<node_id>/status", methods=["GET"])
def proxy_status(node_id):
    payload, err = verify_token()
    if err:
        return jsonify({"error": "unauthorized", "detail": err}), 401

    if node_id not in payload["allowed_nodes"]:
        return jsonify({"error": "access_denied", "node": node_id}), 403

    target = NODE_MAP.get(node_id)
    if not target:
        return jsonify({"error": "node_not_found"}), 404

    res = requests.get(f"{target}/status")
    log_access(payload, node_id, "status", res.status_code)
    return jsonify(res.json())


@app.route("/nodes/<node_id>/exec", methods=["POST"])
def proxy_exec(node_id):
    payload, err = verify_token()
    if err:
        return jsonify({"error": "unauthorized", "detail": err}), 401

    if node_id not in payload["allowed_nodes"]:
        return jsonify({"error": "access_denied", "node": node_id}), 403

    target = NODE_MAP.get(node_id)
    if not target:
        return jsonify({"error": "node_not_found"}), 404

    body = request.get_json() or {}
    res = requests.post(f"{target}/exec", json=body)

    log_access(payload, node_id, f"exec:{body}", res.status_code)
    return jsonify(res.json())


@app.route("/", methods=["GET"])
def home():
    return jsonify({"msg": "CAG Gateway Running"})


def log_access(payload, node, action, status):
    print("==== AUDIT LOG ====")
    print("time:", datetime.datetime.utcnow().isoformat())
    print("user:", payload["sub"])
    print("tenant:", payload["tenant"])
    print("roles:", payload["roles"])
    print("node:", node)
    print("action:", action)
    print("status:", status)
    print("====================")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
