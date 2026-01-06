# pip install Flask flask-cors psycopg2-binary Werkzeug
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
CORS(app)  # 允許前端串接API


# ===== PostgreSQL 連線（用 DATABASE_URL）=====
def get_connection():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("Missing DATABASE_URL env var")
    return psycopg2.connect(db_url)


# ===== 啟動時自動建表=====
def init_db():
    sql = """
    CREATE TABLE IF NOT EXISTS member (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      level TEXT NOT NULL DEFAULT 'normal',
      auth_token TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """
    conn = get_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql)
    finally:
        conn.close()


init_db()


def get_user_by_token(token):
    if not token:
        return None

    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT id, username, level FROM member WHERE auth_token = %s",
                    (token,),
                )
                return cursor.fetchone()
    finally:
        conn.close()


def get_current_user_from_request():
    auth_header = request.headers.get("Authorization", "")
    # 預期格式 Bearer <token>
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    else:
        token = None
    return get_user_by_token(token)


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "缺少username 或 password"}), 400

    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # 檢查帳號是否已經存在
                cursor.execute("SELECT id FROM member WHERE username = %s", (username,))
                exist = cursor.fetchone()
                if exist:
                    return jsonify({"error": "帳號已經存在"}), 400

                # 產生密碼雜湊
                password_hash = generate_password_hash(password)

                # 新增使用者
                cursor.execute(
                    "INSERT INTO member(username, password_hash) VALUES(%s, %s)",
                    (username, password_hash),
                )

        return jsonify({"message": "register ok!"})
    finally:
        conn.close()


# input {"username":"xxxxx"}
@app.route("/api/checkuni", methods=["POST"])
def checkuni():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()

    if not username:
        return jsonify({"error": "必須要輸入帳號確認是否已存在!"}), 400

    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT id FROM member WHERE username = %s", (username,))
                exist = cursor.fetchone()
                if exist:
                    return (
                        jsonify({"status": False, "message": "帳號已經存在, 不能使用"}),
                        200,
                    )
                else:
                    return (
                        jsonify({"status": True, "message": "帳號不存在, 可以使用"}),
                        200,
                    )
    finally:
        conn.close()


# input {"username":"xxxxx", "password":"123456"}
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "缺少username 或 password"}), 400

    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT id, username, password_hash, level FROM member WHERE username = %s",
                    (username,),
                )
                user = cursor.fetchone()

                if not user:
                    return (
                        jsonify(
                            {"message": "登入驗證失敗(帳號錯誤!)", "status": False}
                        ),
                        200,
                    )

                if not check_password_hash(user["password_hash"], password):
                    return (
                        jsonify(
                            {"message": "登入驗證失敗(密碼錯誤!)", "status": False}
                        ),
                        200,
                    )

                # 產生 token 並更新至資料庫
                token = secrets.token_hex(16)
                cursor.execute(
                    "UPDATE member SET auth_token = %s WHERE id = %s",
                    (token, user["id"]),
                )

                return (
                    jsonify(
                        {
                            "message": "登入驗證成功",
                            "username": user["username"],
                            "level": user["level"],
                            "status": True,
                            "token": token,
                        }
                    ),
                    200,
                )
    finally:
        conn.close()


# 驗證token是否合法
@app.route("/api/me", methods=["GET"])
def me():
    user = get_current_user_from_request()
    if not user:
        return jsonify({"error": "未登入或token無效"}), 401
    return jsonify(
        {
            "id": user["id"],
            "username": user["username"],
            "level": user["level"],
            "status": True,
        }
    )


# 讀取所有會員資料(必須是最高權限)
@app.route("/api/admin/users", methods=["GET"])
def admin_get_all_users():
    current_user = get_current_user_from_request()

    if not current_user:
        return jsonify({"error": "未登入或token無效"}), 401

    if current_user["level"] != "admin":
        return jsonify({"error": "沒有權限, 只有admin可以使用這個功能(API)"}), 403

    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT id, username, level, created_at FROM member ORDER BY id DESC"
                )
                users = cursor.fetchall()
                return jsonify({"message": "資料讀取成功", "users": users})
    finally:
        conn.close()


@app.route("/api/ping")
def ping():
    return jsonify({"message": "ping"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
