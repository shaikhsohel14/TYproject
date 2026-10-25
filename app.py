import os
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)
import mysql.connector
from mysql.connector import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get(
    "KH_SECRET_KEY",
    "knowledgehub-college-project-secret"
)

DB_CONFIG = {
    "host": os.environ.get("KH_DB_HOST", "localhost"),
    "user": os.environ.get("KH_DB_USER", "root"),
    "password": os.environ.get("KH_DB_PASSWORD", "SSS@1992"),
    "database": os.environ.get("KH_DB_NAME", "knowledgehub"),
}


def get_db():
    return mysql.connector.connect(**DB_CONFIG)


# Protect pages: users must log in first.
def login_required_page(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return function(*args, **kwargs)
    return wrapper


# Protect database APIs too.
def login_required_api(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Please log in first."}), 401
        return function(*args, **kwargs)
    return wrapper


# Homepage is accessible only after login.
@app.get("/")
@login_required_page
def home():
    return render_template("index.html")


# Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    next_url = request.values.get("next") or "/"

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            cur.execute(
                "SELECT id, name, email, password_hash "
                "FROM users WHERE email = %s",
                (email,)
            )
            user = cur.fetchone()

            if user and check_password_hash(
                user["password_hash"], password
            ):
                session.clear()
                session["user_id"] = user["id"]
                session["user_name"] = user["name"]

                if not next_url.startswith("/") or next_url.startswith("//"):
                    next_url = "/"

                return redirect(next_url)

            error = "Email or password is incorrect."

        except mysql.connector.Error:
            error = "Database connection failed. Check MySQL settings."

        finally:
            if cur:
                cur.close()
            if db and db.is_connected():
                db.close()

    return render_template(
        "login.html",
        mode="login",
        error=error,
        next_url=next_url
    )


# Signup page
@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    next_url = request.values.get("next") or "/"

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or len(password) < 8:
            error = "Enter your name, email, and a password of at least 8 characters."
        else:
            db = None
            cur = None

            try:
                db = get_db()
                cur = db.cursor()

                cur.execute(
                    "INSERT INTO users (name, email, password_hash) "
                    "VALUES (%s, %s, %s)",
                    (name, email, generate_password_hash(password))
                )
                db.commit()

                user_id = cur.lastrowid

                session.clear()
                session["user_id"] = user_id
                session["user_name"] = name

                if not next_url.startswith("/") or next_url.startswith("//"):
                    next_url = "/"

                return redirect(next_url)

            except IntegrityError:
                error = "An account with this email already exists."

            except mysql.connector.Error:
                error = "Database connection failed. Check MySQL settings."

            finally:
                if cur:
                    cur.close()
                if db and db.is_connected():
                    db.close()

    return render_template(
        "login.html",
        mode="signup",
        error=error,
        next_url=next_url
    )


# Logout
@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# Profile page
@app.get("/profile")
@login_required_page
def profile():
    return render_template(
        "profile.html",
        user_name=session.get("user_name", "Reader")
    )


# Get saved books for the logged-in user
@app.get("/api/saved")
@login_required_api
def get_saved():
    db = get_db()
    cur = db.cursor(dictionary=True)

    try:
        cur.execute(
            "SELECT book_id, book_title, saved_at "
            "FROM saved_books WHERE user_id = %s "
            "ORDER BY saved_at DESC",
            (session["user_id"],)
        )
        rows = cur.fetchall()

        for row in rows:
            row["book_url"] = ""
            row["category"] = "Book"

        return jsonify({"books": rows})

    finally:
        cur.close()
        db.close()


# Save or unsave a book
@app.post("/api/saved")
@login_required_api
def toggle_saved():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()

    if not title:
        return jsonify({"error": "Book title is required."}), 400

    db = get_db()
    cur = db.cursor(dictionary=True)

    try:
        cur.execute(
            "SELECT book_id FROM saved_books "
            "WHERE user_id = %s AND book_title = %s",
            (session["user_id"], title)
        )
        row = cur.fetchone()

        if row:
            cur.execute(
                "DELETE FROM saved_books "
                "WHERE user_id = %s AND book_id = %s",
                (session["user_id"], row["book_id"])
            )
            db.commit()
            return jsonify({"saved": False})

        # Stable ID derived from the title.
        book_id = title.lower()

        cur.execute(
            "INSERT INTO saved_books (user_id, book_id, book_title) "
            "VALUES (%s, %s, %s)",
            (session["user_id"], book_id, title)
        )
        db.commit()

        return jsonify({"saved": True})

    finally:
        cur.close()
        db.close()


# Delete a saved book
@app.delete("/api/saved/<book_id>")
@login_required_api
def delete_saved(book_id):
    db = get_db()
    cur = db.cursor()

    try:
        cur.execute(
            "DELETE FROM saved_books "
            "WHERE user_id = %s AND book_id = %s",
            (session["user_id"], book_id)
        )
        db.commit()
        return jsonify({"ok": True})

    finally:
        cur.close()
        db.close()


# Get reading history
@app.get("/api/history")
@login_required_api
def get_history():
    db = get_db()
    cur = db.cursor(dictionary=True)

    try:
        cur.execute(
            "SELECT book_id, book_title, last_read_at "
            "FROM reading_history WHERE user_id = %s "
            "ORDER BY last_read_at DESC LIMIT 100",
            (session["user_id"],)
        )
        rows = cur.fetchall()

        for row in rows:
            if row["last_read_at"]:
                row["last_read_at"] = row["last_read_at"].isoformat()
            row["category"] = "Book"
            row["book_url"] = ""

        return jsonify({"books": rows})

    finally:
        cur.close()
        db.close()


# Add a book to reading history
@app.post("/api/history")
@login_required_api
def add_history():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()

    if not title:
        return jsonify({"error": "Book title is required."}), 400

    book_id = title.lower()
    db = get_db()
    cur = db.cursor()

    try:
        cur.execute(
            "SELECT id FROM reading_history "
            "WHERE user_id = %s AND book_id = %s",
            (session["user_id"], book_id)
        )
        row = cur.fetchone()

        if row:
            cur.execute(
                "UPDATE reading_history "
                "SET book_title = %s, last_read_at = NOW() "
                "WHERE id = %s",
                (title, row[0])
            )
        else:
            cur.execute(
                "INSERT INTO reading_history "
                "(user_id, book_id, book_title, last_read_at) "
                "VALUES (%s, %s, %s, NOW())",
                (session["user_id"], book_id, title)
            )

        db.commit()
        return jsonify({"ok": True})

    finally:
        cur.close()
        db.close()


if __name__ == "__main__":
    app.run(debug=True)