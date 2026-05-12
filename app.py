import uuid
import email
import random
import string
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session
import psycopg2
import bcrypt

load_dotenv()
from datetime import datetime, timedelta
from flask_mail import Mail, Message

from werkzeug.security import generate_password_hash
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

DATABASE_URL = os.getenv('DATABASE_URL')

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
        try:
            # 1. Form se data fetch karna
            username = request.form.get('name')
            email = request.form.get('email')
            password = request.form.get('password')
            plan = request.form.get('plan')

            if not username or not email or not password:
                return "<h1>Error:</h1><p>Please fill all fields.</p>"

            # 2. Password Hashing (Bcrypt)
            password_bytes = password.encode('utf-8')
            hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')

            # 3. License aur OTP details generate karna
            generated_key = str(uuid.uuid4())
            # Expiry date 30 days baad ki
            expiry_date_obj = datetime.now() + timedelta(days=30)
            expiry_date_str = expiry_date_obj.strftime('%d-%m-%Y')

            otp = ''.join(random.choices(string.digits, k=6))
            otp_expiry = datetime.now() + timedelta(minutes=5)

            # 4. Database mein entry save karna
            conn = get_db_connection()
            cursor = conn.cursor()
            
            insert_query = """
                INSERT INTO users 
                (username, email, password, role, license_key, expiry_date, is_verified, otp_code, otp_expiry) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(insert_query, (
                username, 
                email, 
                hashed_password, 
                plan, 
                generated_key, 
                expiry_date_str, 
                False, 
                otp, 
                otp_expiry
            ))
            
            conn.commit()
            cursor.close()
            conn.close()

            # 5. OTP Email bhejna
            try:
                msg = Message('Your OTP Code - LMS Portal',
                              sender=os.getenv('MAIL_USERNAME'),
                              recipients=[email])
                msg.body = f'Your OTP code is: {otp}\n\nThis code will expire in 5 minutes.'
                mail.send(msg)
            except Exception as email_err:
                # Agar email na bhi jaye toh user register ho chuka hai, bas error print ho jaye
                print(f"Mail Error: {email_err}")

            # 6. Session mein email save karke verify page par bhejna
            session['otp_email'] = email
            return redirect(url_for('verify_otp'))

        except Exception as e:
            # Ye line aapko screen par batayegi ke asly masla kya hai
            return f"<h1>Backend Error:</h1><p>{str(e)}</p><br><a href='/register'>Try Again</a>"

    # GET request par registration page dikhana
    return render_template('register.html')
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('otp_email')
    if not email:
        return redirect(url_for('register'))

    error = None
    if request.method == 'POST':
        try:
            # 1. User ka input len aur uske agay peechay se faltu spaces khatam karein
            otp_entered = request.form.get('otp').strip()
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 2. Database se OTP aur Expiry mangwayein
            cursor.execute('SELECT otp_code, otp_expiry FROM public.users WHERE email = %s', (email,))
            user_data = cursor.fetchone()

            if user_data:
                # Database wala OTP bhi string mein convert karein
                db_otp = str(user_data[0]).strip()
                expiry = user_data[1]

                # 3. Dono ko compare karein
                if db_otp == otp_entered:
                    # Time check (tzinfo=None se errors nahi aate)
                    if datetime.now() < expiry.replace(tzinfo=None):
                        cursor.execute('UPDATE public.users SET is_verified = TRUE WHERE email = %s', (email,))
                        conn.commit()
                        session.pop('otp_email', None)
                        cursor.close()
                        conn.close()
                        return redirect(url_for('login')) # Verify ho gaya toh login pe bhej dein
                    else:
                        error = 'OTP expired ho gaya hai! Dubara register karein.'
                else:
                    error = 'Invalid OTP! Email dobara check karein.'
            else:
                error = 'User nahi mila!'
                
            if conn:
                cursor.close()
                conn.close()
                
        except Exception as e:
            error = f"Database Error: {str(e)}"

    return render_template('verify_otp.html', error=error)
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
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
        admin_password = os.getenv('ADMIN_PASSWORD', 'ahmad123')
        if password != admin_password:
            return render_template('admin_login.html', error='Wrong password!')
        session['is_admin'] = True
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()
        conn.close()
        return render_template('admin.html', users=users)
    return render_template('admin_login.html', error=None)

@app.route('/delete/<int:id>')
def delete_user(id):
    if not session.get('is_admin'):
        return redirect(url_for('admin'))
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
@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/refund-policy')
def refund_policy():
    return render_template('refund_policy.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=True)