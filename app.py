import uuid
import email
import random
import string
from flask import Flask, render_template, request, redirect, url_for, session
import psycopg2
from datetime import datetime, timedelta
import flask_mail

app = Flask(__name__)
app.secret_key = 'ahmad_khan_fy_project'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ahmed926475@gmail.com'
app.config['MAIL_PASSWORD'] = 'psui tdqh hdqw ghhg'
mail = flask_mail.Mail(app)

DATABASE_URL = "postgresql://postgres.cqonjkddqxgfyqgcyeqi:navida926475%40@aws-1-ap-northeast-1.pooler.supabase.com:6543/postgres"

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            license_key TEXT,
            expiry_date TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template('register.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        plan = request.form.get('plan')
        generated_key = str(uuid.uuid4())
        expiry_date = (datetime.now() + timedelta(days=30)).strftime('%d-%m-%Y')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, email, password, role, license_key, expiry_date) VALUES (%s, %s, %s, %s, %s, %s)',
                      (username, email, password, plan, generated_key, expiry_date))
        conn.commit()
        conn.close()
        session['username'] = username
        session['user_email'] = email
        session['selected_plan'] = plan
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s AND password = %s', (email, password))
        user = cursor.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['user_email'] = user[2]
            return redirect(url_for('payment'))
        else:
            error = "Invalid Email or Password. Please try again."
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username, license_key FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        display_name = user[0]
        display_key = user[1] if user[1] else "No Key Assigned"
        expiry = (datetime.now() + timedelta(days=30)).strftime('%d-%m-%Y')
        return render_template('dashboard.html', name=display_name, key=display_key, expiry=expiry)
    return "User not found!"

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        password = request.form.get('password')
        if password != 'ahmad123':
            return render_template('admin_login.html', error='Wrong password!')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()
        conn.close()
        return render_template('admin.html', users=users)
    return render_template('admin_login.html', error=None)
@app.route('/delete/<int:id>')
def delete_user(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = %s', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/payment')
def payment():
    user_plan = session.get('selected_plan', 'Standard')
    return render_template('payment.html', plan=user_plan)

@app.route('/process_payment', methods=['POST'])
def process_payment():
    try:
        user_email = request.form.get('email')
        user_id = session.get('user_id')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT license_key FROM users WHERE id = %s', (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        license_key = user_data[0] if user_data else 'N/A'
        msg = flask_mail.Message('License Key Confirmation',
                        sender=app.config['MAIL_USERNAME'],
                        recipients=[user_email])
        msg.body = f"Congratulations! Your payment was successful. Your License Key is: {license_key}"
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
    return render_template('success.html', key=license_key)

@app.route('/watch_movies', methods=['GET', 'POST'])
def watch_movies():
    is_unlocked = False
    error_msg = None
    if request.method == 'POST':
        entered_key = request.form.get('license_key')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE license_key = %s', (entered_key,))
        user_with_key = cursor.fetchone()
        conn.close()
        if user_with_key:
            is_unlocked = True
        else:
            error_msg = "Invalid License Key! Please purchase a plan."
    return render_template('movies.html', is_unlocked=is_unlocked, error_msg=error_msg)

if __name__ == '__main__':
    app.run(debug=True)