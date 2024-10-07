from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import logging

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a strong secret key
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def init_db():
    try:
        conn = sqlite3.connect('site.db')
        cursor = conn.cursor()
        logging.debug("Initializing database...")
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )''')
        conn.commit()
        logging.debug("Users table created or already exists.")
    except Exception as e:
        logging.error(f"Error initializing database: {e}")
    finally:
        conn.close()

def check_tables():
    conn = sqlite3.connect('site.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    conn.close()
    logging.debug("Tables in the database: %s", tables)  # Print existing tables

# Call init_db() and check_tables() when starting the application
init_db()
check_tables()

class User(UserMixin):
    def __init__(self, id, first_name, last_name, email, username, password):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.username = username
        self.password = password

    @staticmethod
    def get(user_id):
        conn = sqlite3.connect('site.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, first_name, last_name, email, username, password FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(*user_data)
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        # طباعة البيانات المدخلة للتحقق
        logging.debug(f"Registering user: {first_name} {last_name}, Email: {email}, Username: {username}")

        conn = sqlite3.connect('site.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (first_name, last_name, email, username, password) VALUES (?, ?, ?, ?, ?)",
                        (first_name, last_name, email, username, hashed_password))
            conn.commit()
            flash('التسجيل ناجح! يمكنك الآن تسجيل الدخول.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('اسم المستخدم أو البريد الإلكتروني موجود بالفعل.', 'danger')
            logging.warning('تمت محاولة التسجيل باستخدام اسم مستخدم أو بريد إلكتروني مكرر.')
        except Exception as e:
            logging.error(f"Error during registration: {e}")
            flash('حدث خطأ أثناء التسجيل.', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('site.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, first_name, last_name, email, username, password FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            user = User(*user_data)
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('welcome'))
            else:
                flash('كلمة المرور غير صالحة.', 'danger')
                logging.warning('Invalid password attempt for user: %s', username)
        else:
            flash('اسم المستخدم غير موجود.', 'danger')
            logging.warning('Login attempt for non-existent user: %s', username)
    
    return render_template('login.html')

@app.route('/welcome')
@login_required
def welcome():
    return render_template('welcome.html', username=current_user.first_name)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
