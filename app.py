import uuid
"""
License Management System (LMS)
Developed by: Ahmad Naveed
Description: This application handles user registration, subscription plans, 
             and automated license key generation after successful payment.
"""
import email
import random
import string
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import uuid
from datetime import datetime, timedelta
import flask_mail
app = Flask(__name__)
app.secret_key = 'ahmad_khan_fy_project' # Security key for sessions

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
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# 1. Home Page (Registration)
@app.route('/')
def home():
    return render_template('register.html')

# 2. Registration Logic
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        plan = request.form.get('plan')

        from datetime import datetime, timedelta
        generated_key = str(uuid.uuid4())
        expiry_date = (datetime.now() + timedelta(days=30)).strftime('%d-%m-%Y')

        conn = get_db_connection()
        cursor = conn.execute('INSERT INTO users (username, email, password, role, license_key, expiry_date) VALUES (?, ?, ?, ?, ?, ?)',
                              (username, email, password, plan, generated_key, expiry_date))
        new_user_id = cursor.lastrowid
        conn.commit()
        conn.close()

        session['user_id'] = new_user_id
        session['username'] = username
        session['user_email'] = email
        session['selected_plan'] = plan

        return redirect(url_for('login'))
    
    return render_template('_db_connection.html')

# 3. Login Logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ? AND password = ?',
                            (email, password)).fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_email'] = user['email']
            return redirect(url_for('payment'))
        else:
            error = "Invalid Email or Password. Please try again."
    return render_template('login.html', error=error)

# 4. User Dashboard (Licentse Key Display)
@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    # Database se username aur REAL license_key uthaein
    user = conn.execute('SELECT username, license_key FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if user:
        display_name = user['username']
        display_key = user['license_key'] if user['license_key'] else "No Key Assigned"
        
        from datetime import datetime, timedelta
        expiry = (datetime.now() + timedelta(days=30)).strftime('%d-%m-%Y')
        return render_template('dashboard.html', name=display_name, key=display_key, expiry=expiry)
    
    return "User not found!"
@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('admin.html', users=users)

# 6. Delete User Logic 
@app.route('/delete/<int:id>')
def delete_user(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin'))

# 7. Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
@app.route('/payment')
def payment():
    # Retrieve the selected plan from the session, defaulting to 'Standard' if not found
    user_plan = session.get('selected_plan', 'Standard') 
    
    # Render the payment page and pass the selected plan to the template
    return render_template('payment.html', plan=user_plan)

@app.route('/process_payment', methods=['POST'])
def process_payment():
    # Keep your existing database and payment logic here

   try:
        # 1. Setup the email message
        user_email = request.form.get('email')
        user_id = session.get('user_id')
        user_data = get_db_connection().execute('SELECT license_key FROM users WHERE id = ?', (user_id,)).fetchone()
        license_key = user_data['license_key'] if user_data else 'N/A'

        msg = flask_mail.Message('License Key Confirmation',
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[user_email])

        msg.body = f"Congratulations! Your payment was successful. Your License Key is: {license_key}"

        # 2. Send the actual email
        mail.send(msg)
        print("Email sent successfully!")

   except Exception as e:
        # 3. Handle errors if the email fails to send
        print(f"Error sending email: {e}")

    # 4. Redirect to the success page
        return render_template('success.html', key=license_key)

@app.route('/watch_movies', methods=['GET', 'POST'])
def watch_movies():
    is_unlocked = False
    error_msg = None
    
    if request.method == 'POST':
        entered_key = request.form.get('license_key')
        
        conn = get_db_connection()
        user_with_key = conn.execute('SELECT * FROM users WHERE license_key = ?', (entered_key,)).fetchone()
        conn.close()

        if user_with_key:
            is_unlocked = True
        else:
            error_msg = "Invalid License Key! Please purchase a plan."

    return render_template('movies.html', is_unlocked=is_unlocked, error_msg=error_msg)

if __name__ == '__main__':
    app.run(debug=True)