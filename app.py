import os
from functools import wraps

import mysql.connector
from mysql.connector import IntegrityError
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

app = Flask(__name__)

# Set KH_SECRET_KEY in Render Environment.
app.secret_key = os.environ.get(
    "KH_SECRET_KEY",
    "local-development-only-change-me",
)

# Set these variables in Render using your Aiven connection details.
DB_CONFIG = {
    "host": os.environ.get("KH_DB_HOST", "localhost"),
    "port": int(os.environ.get("KH_DB_PORT", "3306")),
    "user": os.environ.get("KH_DB_USER", "root"),
    "password": os.environ.get("KH_DB_PASSWORD", ""),
    "database": os.environ.get("KH_DB_NAME", "knowledgehub"),
    "ssl_disabled": False,
    "connection_timeout": 15,
}


def get_db():
    """Connect to MySQL and create the required tables if missing."""
    db = mysql.connector.connect(**DB_CONFIG)
    cur = None

    try:
        cur = db.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS saved_books (
                id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                book_id VARCHAR(255) NOT NULL,
                book_title VARCHAR(500) NOT NULL,
                saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_saved_book (user_id, book_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS reading_history (
                id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                book_id VARCHAR(255) NOT NULL,
                book_title VARCHAR(500) NOT NULL,
                last_read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_history_book (user_id, book_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        db.commit()
        return db

    except Exception:
        db.close()
        raise

    finally:
        if cur:
            cur.close()


def safe_next_url(candidate):
    """Allow only local redirect paths after login or signup."""
    if not candidate or not candidate.startswith("/"):
        return "/"

    if candidate.startswith("//") or candidate.startswith("/\\"):
        return "/"

    return candidate


def login_required_page(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(
                url_for("login", next=request.path)
            )

        return function(*args, **kwargs)

    return wrapper


def login_required_api(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({
                "error": "Please log in first."
            }), 401

        return function(*args, **kwargs)

    return wrapper


# ---------------- HOME ----------------

@app.get("/")
@login_required_page
def home():
    return render_template("index.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    next_url = safe_next_url(request.values.get("next"))

    if request.method == "POST":
        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get("password", "")

        db = None
        cur = None

        try:
            db = get_db()
            cur = db.cursor(dictionary=True)

            cur.execute(
                """
                SELECT id, name, email, password_hash
                FROM users
                WHERE email = %s
                """,
                (email,),
            )

            user = cur.fetchone()

            if user and check_password_hash(
                user["password_hash"], password
            ):
                session.clear()
                session["user_id"] = user["id"]
                session["user_name"] = user["name"]

                return redirect(next_url)

            error = "Email or password is incorrect."

        except mysql.connector.Error:
            app.logger.exception("Database error during login")
            error = (
                "Database connection failed. "
                "Please check the database configuration."
            )

        finally:
            if cur:
                cur.close()

            if db and db.is_connected():
                db.close()

    return render_template(
        "login.html",
        mode="login",
        error=error,
        next_url=next_url,
    )


# ---------------- SIGNUP ----------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    next_url = safe_next_url(request.values.get("next"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get("password", "")

        if not name or not email or len(password) < 8:
            error = (
                "Enter your name, email, and a password "
                "of at least 8 characters."
            )

        else:
            db = None
            cur = None

            try:
                db = get_db()
                cur = db.cursor()

                cur.execute(
                    """
                    INSERT INTO users
                        (name, email, password_hash)
                    VALUES (%s, %s, %s)
                    """,
                    (
                        name,
                        email,
                        generate_password_hash(password),
                    ),
                )

                db.commit()

                new_user_id = cur.lastrowid

                session.clear()
                session["user_id"] = new_user_id
                session["user_name"] = name

                return redirect(next_url)

            except IntegrityError:
                error = (
                    "An account with this email already exists."
                )

            except mysql.connector.Error:
                app.logger.exception("Database error during signup")
                error = (
                    "Database connection failed. "
                    "Please check the database configuration."
                )

            finally:
                if cur:
                    cur.close()

                if db and db.is_connected():
                    db.close()

    return render_template(
        "login.html",
        mode="signup",
        error=error,
        next_url=next_url,
    )


# ---------------- LOGOUT ----------------

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- PROFILE ----------------

@app.get("/profile")
@login_required_page
def profile():
    return render_template(
        "profile.html",
        user_name=session.get("user_name", "Reader"),
    )


# ---------------- GET SAVED BOOKS ----------------

@app.get("/api/saved")
@login_required_api
def get_saved():
    db = None
    cur = None

    try:
        db = get_db()
        cur = db.cursor(dictionary=True)

        cur.execute(
            """
            SELECT book_id, book_title, saved_at
            FROM saved_books
            WHERE user_id = %s
            ORDER BY saved_at DESC
            """,
            (session["user_id"],),
        )

        rows = cur.fetchall()

        for row in rows:
            if row.get("saved_at"):
                row["saved_at"] = row["saved_at"].isoformat()

            row["book_url"] = ""
            row["category"] = "Book"

        return jsonify({"books": rows})

    except mysql.connector.Error:
        app.logger.exception("Error fetching saved books")
        return jsonify({
            "error": "Could not load saved books."
        }), 500

    finally:
        if cur:
            cur.close()

        if db and db.is_connected():
            db.close()


# ---------------- SAVE OR UNSAVE BOOK ----------------

@app.post("/api/saved")
@login_required_api
def toggle_saved():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()

    if not title:
        return jsonify({
            "error": "Book title is required."
        }), 400

    book_id = title.lower()[:255]
    db = None
    cur = None

    try:
        db = get_db()
        cur = db.cursor(dictionary=True)

        cur.execute(
            """
            SELECT book_id
            FROM saved_books
            WHERE user_id = %s AND book_id = %s
            """,
            (session["user_id"], book_id),
        )

        existing = cur.fetchone()

        if existing:
            cur.execute(
                """
                DELETE FROM saved_books
                WHERE user_id = %s AND book_id = %s
                """,
                (session["user_id"], book_id),
            )

            db.commit()
            return jsonify({"saved": False})

        cur.execute(
            """
            INSERT INTO saved_books
                (user_id, book_id, book_title)
            VALUES (%s, %s, %s)
            """,
            (
                session["user_id"],
                book_id,
                title[:500],
            ),
        )

        db.commit()
        return jsonify({"saved": True})

    except mysql.connector.Error:
        app.logger.exception("Error saving or removing a book")
        return jsonify({
            "error": "Could not save the book."
        }), 500

    finally:
        if cur:
            cur.close()

        if db and db.is_connected():
            db.close()


# ---------------- DELETE SAVED BOOK ----------------

@app.delete("/api/saved/<path:book_id>")
@login_required_api
def delete_saved(book_id):
    db = None
    cur = None

    try:
        db = get_db()
        cur = db.cursor()

        cur.execute(
            """
            DELETE FROM saved_books
            WHERE user_id = %s AND book_id = %s
            """,
            (session["user_id"], book_id),
        )

        db.commit()
        return jsonify({"ok": True})

    except mysql.connector.Error:
        app.logger.exception("Error deleting a saved book")
        return jsonify({
            "error": "Could not delete the saved book."
        }), 500

    finally:
        if cur:
            cur.close()

        if db and db.is_connected():
            db.close()


# ---------------- GET READING HISTORY ----------------

@app.get("/api/history")
@login_required_api
def get_history():
    db = None
    cur = None

    try:
        db = get_db()
        cur = db.cursor(dictionary=True)

        cur.execute(
            """
            SELECT book_id, book_title, last_read_at
            FROM reading_history
            WHERE user_id = %s
            ORDER BY last_read_at DESC
            LIMIT 100
            """,
            (session["user_id"],),
        )

        rows = cur.fetchall()

        for row in rows:
            if row.get("last_read_at"):
                row["last_read_at"] = (
                    row["last_read_at"].isoformat()
                )

            row["category"] = "Book"
            row["book_url"] = ""

        return jsonify({"books": rows})

    except mysql.connector.Error:
        app.logger.exception("Error fetching reading history")
        return jsonify({
            "error": "Could not load reading history."
        }), 500

    finally:
        if cur:
            cur.close()

        if db and db.is_connected():
            db.close()


# ---------------- ADD TO READING HISTORY ----------------

@app.post("/api/history")
@login_required_api
def add_history():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()

    if not title:
        return jsonify({
            "error": "Book title is required."
        }), 400

    book_id = title.lower()[:255]
    db = None
    cur = None

    try:
        db = get_db()
        cur = db.cursor()

        cur.execute(
            """
            SELECT id
            FROM reading_history
            WHERE user_id = %s AND book_id = %s
            """,
            (session["user_id"], book_id),
        )

        existing = cur.fetchone()

        if existing:
            cur.execute(
                """
                UPDATE reading_history
                SET book_title = %s, last_read_at = NOW()
                WHERE id = %s
                """,
                (title[:500], existing[0]),
            )

        else:
            cur.execute(
                """
                INSERT INTO reading_history
                    (user_id, book_id, book_title, last_read_at)
                VALUES (%s, %s, %s, NOW())
                """,
                (
                    session["user_id"],
                    book_id,
                    title[:500],
                ),
            )

        db.commit()
        return jsonify({"ok": True})

    except mysql.connector.Error:
        app.logger.exception("Error updating reading history")
        return jsonify({
            "error": "Could not update reading history."
        }), 500

    finally:
        if cur:
            cur.close()

        if db and db.is_connected():
            db.close()


# ---------------- START APP ----------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
