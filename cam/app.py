from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)

SECRET_KEY = "super-secret-demo-key"   # demo用，真实系统不会这样

# 模拟一个简单用户数据库
USERS = {
    "alice": {
        "password": "123456",
        "tenant": "tenant-1",
        "roles": ["ops"],
        "allowed_nodes": ["node-1", "node-2"]
    },
    "bob": {
        "password": "123456",
        "tenant": "tenant-2",
        "roles": ["viewer"],
        "allowed_nodes": ["node-2"]
    }
}

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    if username not in USERS or USERS[username]["password"] != password:
        return jsonify({"error": "invalid_credentials"}), 401

    user_info = USERS[username]

    payload = {
        "sub": username,
        "tenant": user_info["tenant"],
        "roles": user_info["roles"],
        "allowed_nodes": user_info["allowed_nodes"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600
    })

@app.route("/auth/introspect", methods=["POST"])
def introspect():
    data = request.get_json() or {}
    token = data.get("token")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"valid": True, "payload": payload})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 401

@app.route("/", methods=["GET"])
def home():
    return jsonify({"msg": "CAM Service Running"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
