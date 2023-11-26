from flask import Flask, render_template, request, redirect, url_for, flash, session
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Sample user data (in-memory storage, not suitable for production)
users = []

def get_user(username):
    for user in users:
        if user['username'] == username:
            return user
    return None

def generate_session():
    session['token'] = bcrypt.gensalt().decode('utf-8')

def register(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    user = {'username': username, 'password': hashed_password}
    users.append(user)
    flash('Registration successful!', 'success')

def login(username, password):
    user = get_user(username)
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        generate_session()
        flash(f'Welcome {username}! Login successful.', 'success')
        return True
    else:
        flash('Invalid credentials. Please try again.', 'error')
        return False

def logout():
    session.pop('token', None)
    flash('Logged out successfully!', 'success')

def is_authenticated():
    return 'token' in session

def get_username():
    return session.get('username', '')

@app.route('/')
def home():
    return 'Welcome to the home page!'

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        register(username, password)
        return redirect(url_for('login_page'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if login(username, password):
            session['username'] = username
            return redirect(url_for('secured_page'))
    return render_template('login.html')

@app.route('/logout')
def logout_page():
    if is_authenticated():
        logout()
    return redirect(url_for('home'))

@app.route('/secured')
def secured_page():
    if is_authenticated():
        return f'Hello {get_username()}! This is the secured page.'
    else:
        flash('You are not logged in. Please log in.', 'error')
        return redirect(url_for('login_page'))

if __name__ == '__main__':
    app.run(debug=True)
