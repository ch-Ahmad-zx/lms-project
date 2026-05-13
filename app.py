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
        plan = request.form.get('plan', 'Standard') # Default plan agar form mein na ho

        if not username or not email or not password:
            return render_template('register.html', error="Please fill all fields.")

        # 1. Password Hashing (Werkzeug - Consistent with Login)
        hashed_password = generate_password_hash(password)

        # 2. License aur OTP details generate karna
        generated_key = str(uuid.uuid4())
        
        # Expiry date 30 days baad ki
        expiry_date_obj = datetime.now() + timedelta(days=30)
        expiry_date_str = expiry_date_obj.strftime('%Y-%m-%d %H:%M:%S')

        otp = ''.join(random.choices(string.digits, k=6))
        otp_expiry = datetime.now() + timedelta(minutes=5)

        # 3. Database mein entry save karna
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
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

            # 4. OTP Email bhejha
            try:
                msg = Message('Your OTP Code - LMS Portal',
                            sender=os.getenv('MAIL_USERNAME'),
                            recipients=[email])
                msg.body = f'Your OTP code is: {otp}\n\nThis code will expire in 5 minutes.'
                mail.send(msg)
            except Exception as email_err:
                print(f"Mail Error: {email_err}")

            # 5. Session mein save karke verify page par bhejna
            session['otp_email'] = email
            return redirect(url_for('verify_otp'))

        except Exception as e:
            conn.rollback()
            # Agar email pehle se hai toh professional error dikhao
            if "already exists" in str(e) or "unique constraint" in str(e):
                return render_template('register.html', error="This email is already registered. Please Login.")
            
            # Baqi kisi bhi backend error ke liye
            return f"<h1>Backend Error:</h1><p>{str(e)}</p><a href='/register'>Try Again</a>"
            
        finally:
            cursor.close()
            conn.close()

    # GET request par sirf page dikhao
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

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Database se user fetch karein
            cursor.execute('SELECT id, email, password, is_verified FROM public.users WHERE email = %s', (email,))
            user = cursor.fetchone()
            
            if user:
                u_id, u_email, u_hashed_password, u_verified = user
                
                if not u_verified:
                    return render_template('login.html', error="Please verify your email first!")

                # YAHAN ASAL TABDEELI HAI:
                # Hashed password ko input password se match karna
                if check_password_hash(u_hashed_password, password):
                    session['user_id'] = u_id
                    session['email'] = u_email
                    return redirect(url_for('payment'))
                else:
                    return render_template('login.html', error="Invalid email or password.")
            else:
                return render_template('login.html', error="User not found.")

        except Exception as e:
            return f"Login Error: {str(e)}"
        finally:
            if conn:
                cursor.close()
                conn.close()

    return render_template('login.html')
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Database se user ki details nikalein
    cursor.execute('SELECT license_key, expiry_date FROM public.users WHERE id = %s', (user_id,))
    user_data = cursor.fetchone()
    
    conn.close()

    if user_data:
        l_key = user_data[0]
        # Expiry date ko format karein taake achi lagay
        e_date = user_data[1] # Agar database mein string hai toh formatting ki zaroorat nahi
        return render_template('dashboard.html', license_key=l_key, expiry_date=e_date)
    
    return "User data not found."

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