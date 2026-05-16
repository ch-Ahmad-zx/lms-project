import uuid
import random
import string
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session
import psycopg2
from datetime import datetime, timedelta
from flask_mail import Mail, Message

# Hashing ke liye sirf ye dono tools chahiye
from werkzeug.security import generate_password_hash, check_password_hash

# Environment variables load karein
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

# Email Configuration
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
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        plan = request.form.get('plan', 'Basic')

        # Agar koi cheez khali hai toh error dikhao aur data wapas bhejo
        if not username or not email or not password:
            return render_template('register.html', error="Please fill all fields.", username=username, email=email)

        try:
            hashed_password = generate_password_hash(password)
            generated_key = str(uuid.uuid4())
            expiry_date_str = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
            otp = ''.join(random.choices(string.digits, k=6))
            otp_expiry = datetime.now() + timedelta(minutes=5)

            conn = get_db_connection()
            cursor = conn.cursor()

            insert_query = """
                INSERT INTO users 
                (username, email, password, role, license_key, expiry_date, is_verified, otp_code, otp_expiry)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (username, email, hashed_password, plan, generated_key, expiry_date_str, False, otp, otp_expiry))
            conn.commit()

            # Email bhejte hain
            msg = Message('Your OTP Code', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
            msg.body = f'Your OTP is: {otp}'
            mail.send(msg)

            session['otp_email'] = email
            return redirect(url_for('verify_otp'))

        except Exception as e:
            if conn: conn.rollback()
            # AGAR EMAIL PEHLE SE HAI TO YAHAN ERROR HANDLE HOGA
            error_msg = "This email is already registered. Please Login." if "already exists" in str(e).lower() else f"Error: {str(e)}"
            return render_template('register.html', error=error_msg, username=username, email=email)
        
        finally:
            if cursor: cursor.close()
            if conn: conn.close()

    return render_template('register.html')
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('otp_email')
    if not email:
        return redirect(url_for('register'))

    error = None
    if request.method == 'POST':
        try:
            # Taking input and removing any accidental spaces
            otp_entered = request.form.get('otp').strip()
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Fetching OTP and Expiry from database
            cursor.execute('SELECT otp_code, otp_expiry FROM public.users WHERE email = %s', (email,))
            user_data = cursor.fetchone()

            if user_data:
                db_otp = str(user_data[0]).strip()
                expiry = user_data[1]

                # Debugging: Match exact values
                if db_otp == otp_entered:
                    # Expiry Check
                    if datetime.now() < expiry.replace(tzinfo=None):
                        # Update user status to verified
                        cursor.execute('UPDATE public.users SET is_verified = TRUE WHERE email = %s', (email,))
                        conn.commit()
                        session.pop('otp_email', None)
                        cursor.close()
                        conn.close()
                        return redirect(url_for('login'))
                    else:
                        error = 'OTP has expired! Please register again.'
                else:
                    error = 'Invalid OTP! Please check your email and try again.'
            else:
                error = 'User session not found. Please register again.'
                
            if conn:
                cursor.close()
                conn.close()
                
        except Exception as e:
            error = f"System Error: {str(e)}"

    return render_template('verify_otp.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form.get('email').strip().lower()
        password = request.form.get('password').strip()

        # =========================
        # ADMIN LOGIN
        # =========================

        if email == "admin@gmail.com" and password == "admin123":

            session.clear()

            session.permanent = True
            session['user_id'] = 0
            session['email'] = email
            session['is_admin'] = True

            return redirect(url_for('admin'))

        # =========================
        # NORMAL USER LOGIN
        # =========================

        try:

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, email, password, is_verified
                FROM public.users
                WHERE email = %s
            """, (email,))

            user = cursor.fetchone()

            if user:

                u_id, u_email, u_hashed_password, u_verified = user

                # Email verification check
                if not u_verified:
                    return render_template(
                        'login.html',
                        error="Please verify your email first!"
                    )

                # Password check
                if check_password_hash(u_hashed_password, password):

                    session.clear()

                    session.permanent = True
                    session['user_id'] = u_id
                    session['email'] = u_email
                    session['is_admin'] = False

                    return redirect(url_for("payment"))

                else:
                    return render_template(
                        'login.html',
                        error="Invalid email or password."
                    )

            else:
                return render_template(
                    'login.html',
                    error="User not found."
                )

        except Exception as e:
            return f"Login Error: {str(e)}"

        finally:
            if conn:
                cursor.close()
                conn.close()

    return render_template('login.html')
@app.route('/subscription')
def subscription():

    if 'user_id' not in session:
        return redirect(url_for('login'))

    return render_template('subscription.html')
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT license_key, expiry_date FROM public.users WHERE id = %s', (user_id,))
        user_data = cursor.fetchone()

        if user_data:
            # Agar license key nahi hai toh subscription par bhejein
            if not user_data[0]:
                return redirect(url_for('subscription'))
            
            return render_template('dashboard.html', license_key=user_data[0], expiry_date=user_data[1])
        else:
            return "User data not found."
            
    except Exception as e:
        return f"Dashboard Error: {str(e)}"
    finally:
        if conn:
            cursor.close()
            conn.close()
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    error = None
    session.pop('is_admin', None)
    if request.method == 'POST':
        password = request.form.get('password')
        if password == 'ahmad123':
            session['is_admin'] = True
            return redirect(url_for('admin'))
        else:
            error = 'Wrong password!'
    
    if not session.get('is_admin'):
        return render_template('admin_login.html', error=error)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, username, email, role, license_key, expiry_date
        FROM users
        ORDER BY id DESC
    """)

    all_users = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin.html', users=all_users)
@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    # Security check: sirf admin hi delete kar sakay
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
    except Exception as e:
        print(f"Delete Error: {e}")
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('admin'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
@app.route('/google117b5501cbc5a1a8.html')
def google_verify():
    return 'google-site-verification: google117b5501cbc5a1a8.html'
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM public.users WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            if user:
                otp = ''.join(random.choices(string.digits, k=6))
                otp_expiry = datetime.now() + timedelta(minutes=5)
                
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE public.users SET otp_code = %s, otp_expiry = %s WHERE email = %s",
                             (otp, otp_expiry, email))
                conn.commit()
                cursor.close()
                conn.close()

                msg = Message('Password Reset OTP',
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[email])
                msg.body = f'Your OTP for password reset is: {otp}'
                mail.send(msg)

                session['reset_email'] = email
                return redirect(url_for('reset_password'))
            else:
                return render_template('forgot_password.html', error='Email not found!')
        except Exception as e:
            return render_template('forgot_password.html', error=f'Error: {str(e)}')
    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')
    if not email:
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        otp = request.form.get('otp').strip()
        new_password = request.form.get('new_password')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT otp_code, otp_expiry FROM public.users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user:
                db_otp = str(user[0]).strip()
                expiry = user[1]

                if db_otp == otp and datetime.now() < expiry.replace(tzinfo=None):
                    hashed = generate_password_hash(new_password)
                    cursor.execute("UPDATE public.users SET password = %s WHERE email = %s",
                                 (hashed, email))
                    conn.commit()
                    session.pop('reset_email', None)
                    cursor.close()
                    conn.close()
                    return redirect(url_for('login'))
                else:
                    return render_template('reset_password.html', error='Invalid or expired OTP!')
            cursor.close()
            conn.close()
        except Exception as e:
            return render_template('reset_password.html', error=f'Error: {str(e)}')
    
    return render_template('reset_password.html')

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
    return redirect(url_for('success', key=license_key))
@app.route('/success')
def success():
    key = request.args.get('key')
    return render_template('success.html', key=key)

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