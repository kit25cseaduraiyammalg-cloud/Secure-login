from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "secure_secret_key"

# Database Setup
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# Home
@app.route("/")
def home():
    return redirect("/login")

# Register
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3:
            flash("Username too short")
            return redirect("/register")

        if len(password) < 6:
            flash("Password must be at least 6 characters")
            return redirect("/register")

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users(username,password) VALUES(?,?)",
                (username, hashed_password)
            )

            conn.commit()
            conn.close()

            flash("Registration Successful")
            return redirect("/login")

        except:
            flash("Username already exists")
            return redirect("/register")

    return render_template("register.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user:

            stored_password = user[2]

            if bcrypt.checkpw(
                password.encode("utf-8"),
                stored_password
            ):

                session["user"] = username
                return redirect("/dashboard")

        flash("Invalid Credentials")
        return redirect("/login")

    return render_template("login.html")

# Dashboard
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["user"]
    )

# Logout
@app.route("/logout")
def logout():

    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)
