from flask import Flask, redirect, render_template, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from cs50 import SQL
from helper import login_required
from datetime import datetime
import socket

# Configure the application
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
db = SQL("sqlite:///database.db")

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response
#------------------------------------------------------------ADMIN PAGE----------------------------------------------------------#
@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    logs = db.execute("SELECT users.username, date, computer_name, ip FROM user_logs INNER JOIN users ON user_logs.user_id = users.id")
    tickets = db.execute("SELECT title, statuses.name, statuses.color, users.username FROM tickets, statuses, users WHERE tickets.status_id = statuses.id AND tickets.user_id = users.id")
    return render_template("admin.html", logs=logs, tickets=tickets)

#------------------------------------------------------------AGENT PAGE----------------------------------------------------------#
@app.route("/agent", methods=["GET", "POST"])
@login_required
def agent():
    user_id = session['user_id']
    name = session['name']
    tickets = db.execute("SELECT tickets.id,title, statuses.name, statuses.color, users.username, tickets.created_at FROM tickets,statuses, users WHERE statuses.id = tickets.status_id AND tickets.user_id = users.id AND tickets.agent_id = ?",user_id)
    open_tickets = db.execute("SELECT tickets.id,title, statuses.name, statuses.color, tickets.created_at, users.username FROM tickets,statuses, users WHERE statuses.id = tickets.status_id AND users.id = tickets.user_id AND tickets.open = true AND tickets.agent_id IS NULL")
    return render_template("agent.html", tickets=tickets, name=name, open_tickets=open_tickets)

@app.route("/take-it/<ticket_id>", methods=['GET'])
@login_required
def take_it(ticket_id):
        db.execute('UPDATE tickets SET agent_id = ? WHERE id = ?', session['user_id'], ticket_id)
        return redirect("/agent")

#------------------------------------------------------------INDEX PAGE----------------------------------------------------------#
@app.route("/")
@login_required
def index():
    user_id = session['user_id']
    name = session['name']
    role = session['role']
    if role == "Admin":
        return redirect("/admin")
    if role == "Agent":
        return redirect("/agent")

    tickets = db.execute("SELECT tickets.id, tickets.title, statuses.name, statuses.color, tickets.user_id, tickets.created_at FROM tickets, statuses WHERE tickets.status_id=statuses.id AND tickets.user_id = ?", user_id)
    return render_template('index.html', user_id=user_id, name=name, role=role, tickets=tickets)


#------------------------------------------------------------TICKET DETAIL PAGE----------------------------------------------------------#
@app.route("/ticket-detail/<ticket_id>", methods=["GET"])
@login_required
def ticket_detail(ticket_id):
    ticket = db.execute("SELECT tickets.id, tickets.title, statuses.name, statuses.color, tickets.content, users.username, tickets.created_at FROM tickets, statuses, users WHERE tickets.status_id=statuses.id AND tickets.agent_id = users.id AND tickets.id = ?", ticket_id)
    comments = db.execute("SELECT comments.comment, comments.created_at, users.username FROM comments, tickets, users WHERE users.id = comments.user_id AND comments.ticket_id = ?", ticket_id)
    statuses = db.execute("SELECT * FROM statuses")
    return render_template('ticket-detail.html', ticket=ticket[0], comments=comments, statuses=statuses)

@app.route("/add-comment/<ticket_id>", methods=["POST"])
@login_required
def add_comment(ticket_id):
    if request.method == 'POST':
        if request.form.get('comment'):
            db.execute("INSERT INTO comments(ticket_id, comment, created_at, user_id) VALUES(?, ?, ?, ?)", ticket_id, request.form.get('comment'), datetime.now(), session['user_id'] )
            return redirect(f"/ticket-detail/{ticket_id}")

#------------------------------------------------------------LOGIN PAGE----------------------------------------------------------#
@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        if not request.form.get('username'):
            flash("Must provide username")
            return redirect("/login")
        if not request.form.get('password'):
            flash("Must provide password")
            return redirect("/login")
        user_info = db.execute("SELECT * FROM users WHERE username = ?", request.form.get('username'))

        if len(user_info) != 1 or not check_password_hash(user_info[0]['hash'], request.form.get('password')):
            flash("Invalid username and/or password")
            return redirect("/login")

        session["user_id"] = user_info[0]['id']
        session["name"] = user_info[0]['first_name']
        session["role"] = db.execute("SELECT name FROM roles WHERE id = ?", user_info[0]['role_id'])[0]['name']
        db.execute(
            "INSERT INTO user_logs (user_id, date, computer_name, ip) VALUES(?, ?, ?, ?)",
            int(user_info[0]['id']), datetime.now(), socket.gethostname(), socket.gethostbyname(socket.gethostname()))
        if session["role"]=="Admin":
            return redirect("admin")
        return redirect("/")
    return render_template("login.html")

#------------------------------------------------------------LOGOUT PAGE----------------------------------------------------------#
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")



#------------------------------------------------------------USERS PAGE----------------------------------------------------------#
@app.route("/users")
@login_required
def users():
    users = db.execute("SELECT * FROM users")
    return render_template("users.html", users=users)

#------------------------------------------------------------ADD TICKET PAGE----------------------------------------------------------#
@app.route("/add-ticket", methods=["GET", "POST"])
@login_required
def add_ticket():
    user_id = session['user_id']
    title = request.form.get('title')
    content = request.form.get('content')
    created_at = datetime.now()

    if request.method =="POST":
        if not title or not content:
            flash ("Wrong input.")
            return redirect("add-ticket")
        db.execute("INSERT INTO tickets(title, content,status_id, user_id, created_at) VALUES (?, ?, 1, ?, ?)",
        title, content, user_id, created_at)
        flash("Create Successfully")
        return redirect("add-ticket")

    return render_template('add-ticket.html')

#------------------------------------------------------------ADD USER PAGE----------------------------------------------------------#
@app.route("/add-user", methods=["GET", "POST"])
@login_required
def add_user():
    if request.method == "POST":
        first_name = request.form.get("firstname")
        last_name = request.form.get("lastname")
        username = request.form.get("username")
        password = generate_password_hash(request.form.get("password"))
        email = request.form.get("email")
        role_id =  request.form.get("role_select")
        db.execute(
            "INSERT INTO users (first_name, last_name, username, hash, email, role_id) VALUES (?, ?, ?, ?, ?, ?)", first_name, last_name, username, password, email, role_id
            )
        flash("Successful")
        return redirect("/add-user")

    roles = db.execute("SELECT * FROM roles")
    users = db.execute("SELECT first_name, last_name, username, role_id FROM users")
    return render_template("add-user.html",users=users, roles=roles)

#------------------------------------------------------------ADD-ROLE PAGE----------------------------------------------------------#
@app.route("/add-role", methods=["GET", "POST"])
@login_required
def add_role():
    if request.method == "POST":
        role_name = request.form.get("role_name")
        if role_name.isalnum():
            roles = db.execute("SELECT * FROM roles WHERE name = ?", role_name)
            if len(roles)==0:
                db.execute(
                "INSERT INTO roles (name) VALUES (?)", role_name
                )
                flash("Successful")
                return redirect("/add-role")
    roles = db.execute("SELECT * FROM roles")
    return render_template("add-role.html", roles=roles)


#------------------------------------------------------------ADD STATUS PAGE----------------------------------------------------------#
@app.route("/add-status", methods=["GET", "POST"])
@login_required
def add_status():
    if request.method == "POST":
        status_name = request.form.get('name')
        status_color = request.form.get('color')
        if not status_name.isalpha():
            flash("Name must be alphabet")
            return redirect("/add-status")
        status = db.execute("SELECT * FROM statuses WHERE name = ?", status_name)
        if len(status)!=0:
            flash("Name is repetitious")
            return redirect("/add-status")

        db.execute(
                "INSERT INTO statuses (name, color) VALUES (?, ?)", status_name, status_color
                )
        flash("Successful")
        return redirect("/add-status")
    statuses = db.execute("SELECT * FROM statuses")
    return render_template("add-status.html", statuses=statuses)