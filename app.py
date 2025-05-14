from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Замените на надежный секретный ключ

DATABASE = 'fpv_courses.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """)
        
        db.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        db.commit()


def hash_password(password):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + key

def verify_password(stored_hash, password):
    salt = stored_hash[:16]
    key = stored_hash[16:]
    new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return key == new_key


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите для доступа к этой странице', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/main')
def main_page():
    return render_template('main.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/curs1')
def curs1():
    return render_template('curs1.html')

@app.route('/curs2')
def curs2():
    return render_template('curs2.html')

@app.route('/curs3')
def curs3():
    return render_template('curs3.html')

@app.route('/curs4')
def curs4():
    return render_template('curs4.html')

@app.route('/curs5')
def curs5():
    return render_template('curs5.html')

@app.route('/curs6')
def curs6():
    return render_template('curs6.html')

@app.route('/contacts', methods=['GET', 'POST'])
def contacts():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Сохраняем в базу данных
        try:
            with get_db() as db:
                db.execute(
                    'INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)',
                    (name, email, message)
                )
                db.commit()
            flash('Ваше сообщение отправлено! Мы свяжемся с вами в ближайшее время.', 'success')
        except sqlite3.Error as e:
            flash('Произошла ошибка при сохранении сообщения. Пожалуйста, попробуйте позже.', 'error')
            app.logger.error(f"Ошибка при сохранении контакта: {e}")

        return redirect(url_for('contacts'))

    return render_template('contacts.html')

# Маршруты аутентификации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Пароли не совпадают!', 'error')
            return redirect(url_for('register'))

        password_hash = hash_password(password)

        try:
            with get_db() as db:
                db.execute(
                    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                    (username, email, password_hash)
                )
                db.commit()
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Имя пользователя или email уже заняты', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db() as db:
            user = db.execute(
                'SELECT * FROM users WHERE username = ?',
                (username,)
            ).fetchone()

        if user and verify_password(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('main_page'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Вы вышли из системы', 'success')
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404





if __name__ == '__main__':
    init_db()  # Инициализация базы данных
    app.run(debug=True)