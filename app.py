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
      edu TEXT,
      city TEXT,
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
                    "SELECT id, username, level, created_at FROM member ORDER BY id"
                )
                users = cursor.fetchall()
                return jsonify({"message": "資料讀取成功", "users": users})
    finally:
        conn.close()


@app.route("/api/admin/level", methods=["GET"])
def admin_level():
    # 確認有沒有登入(token is ok?)
    current_user = get_current_user_from_request()

    if not current_user:
        return jsonify({"error": "未登入或token not ok"}), 401
    # 確認是否為admin
    if current_user["level"] != "admin":
        return jsonify({"error": "沒有權限!"}), 403
    # 列出所有會員資料
    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as curor:
                curor.execute(
                    "SELECT level, COUNT(*) as count FROM member GROUP BY level"
                )
                rows = curor.fetchall()

                # 回傳所有會員等級統計資料
                return jsonify({"message": "會員等級資料", "data": rows})
    finally:
        conn.close()


@app.route("/api/admin/edu", methods=["GET"])
def admin_edu():
    # 確認有沒有登入(token is ok?)
    current_user = get_current_user_from_request()

    if not current_user:
        return jsonify({"error": "未登入或token not ok"}), 401
    # 確認是否為admin
    if current_user["level"] != "admin":
        return jsonify({"error": "沒有權限!"}), 403
    # 列出所有會員資料
    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as curor:
                curor.execute("SELECT edu, COUNT(*) as count FROM member GROUP BY edu")
                rows = curor.fetchall()

                # 回傳所有會員等級統計資料
                return jsonify({"message": "會員學歷資料", "data": rows})
    finally:
        conn.close()


@app.route("/api/admin/city", methods=["GET"])
def admin_city():
    # 確認有沒有登入(token is ok?)
    current_user = get_current_user_from_request()

    if not current_user:
        return jsonify({"error": "未登入或token not ok"}), 401
    # 確認是否為admin
    # if current_user["level"] != "admin":
    #     return jsonify({"error": "沒有權限!"}), 403
    # 列出所有會員資料
    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as curor:
                curor.execute(
                    "SELECT city, COUNT(*) as count FROM member GROUP BY city"
                )
                rows = curor.fetchall()

                # 回傳所有會員等級統計資料
                return jsonify({"message": "會員居住地資料", "data": rows})
    finally:
        conn.close()


# for barfoods
@app.route("/api/barfoods/list", methods=["GET"])
def barfoods_list():
    # 確認有沒有登入(token is ok?)
    current_user = get_current_user_from_request()

    if not current_user:
        return jsonify({"error": "未登入或token not ok"}), 401
    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as curor:
                curor.execute("SELECT id, name, price, qty, downtime FROM barfoods ")
                rows = curor.fetchall()

                # 回傳所有食物資料
                return jsonify({"message": "接收資料成功!", "data": rows})
    finally:
        conn.close()


@app.route("/api/barfoods/add", methods=["POST"])
def barfoods_add():
    # 確認有沒有登入(token is ok?)
    current_user = get_current_user_from_request()

    if not current_user:
        return jsonify({"error": "未登入或token not ok"}), 401

    data = request.get_json(silent=True) or {}

    name = (data.get("name") or "").strip()
    price = (data.get("price") or "").strip()
    qty = (data.get("qty") or "").strip()
    downtime = (data.get("downtime") or "").strip()

    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # 新增上架物品
                cursor.execute(
                    "INSERT INTO barfoods(name, price, qty, downtime) VALUES(%s, %s, %s, %s)",
                    (name, price, qty, downtime),
                )
        return jsonify({"message": "add ok!"})
    finally:
        conn.close()


@app.route("/api/barfoods/update", methods=["POST"])
def barfoods_update():
    # 確認有沒有登入(token is ok?)
    current_user = get_current_user_from_request()

    if not current_user:
        return jsonify({"error": "未登入或token not ok"}), 401

    data = request.get_json(silent=True) or {}

    id = (data.get("id") or "").strip()
    name = (data.get("name") or "").strip()
    price = (data.get("price") or "").strip()
    qty = (data.get("qty") or "").strip()
    downtime = (data.get("downtime") or "").strip()

    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # 新增上架物品
                cursor.execute(
                    f"UPDATE barfoods SET name='{name}', price={price}, qty={qty}, downtime='{downtime}' WHERE id = {id};",
                )
        return jsonify({"message": "update ok!"})
    finally:
        conn.close()


@app.route("/api/barfoods/delete", methods=["POST"])
def barfoods_delete():
    # 確認有沒有登入(token is ok?)
    current_user = get_current_user_from_request()

    if not current_user:
        return jsonify({"error": "未登入或token not ok"}), 401

    data = request.get_json(silent=True) or {}

    id = (data.get("id") or "").strip()

    conn = get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # 新增上架物品
                cursor.execute(
                    "DELETE FROM barfoods WHERE id = %s;",
                    (id),
                )
        return jsonify({"message": "delete ok!"})
    finally:
        conn.close()


# 修復id
@app.route("/api/fix-barfoods-seq", methods=["POST"])
def fix_barfoods_sequence():
    current_user = get_current_user_from_request()
    if not current_user:
        return jsonify({"error": "未登入"}), 401

    conn = get_connection()
    try:
        with conn:
            with conn.cursor() as cursor:
                # 重置序列到當前最大 id
                cursor.execute(
                    """
                    SELECT setval('barfoods_id_seq', 
                                   GREATEST(1, COALESCE((SELECT MAX(id) FROM barfoods), 0))
                                  );
                """
                )
        return jsonify({"message": "序列已修復！"})
    finally:
        conn.close()


@app.route("/api/ping")
def ping():
    return jsonify({"message": "ping"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
