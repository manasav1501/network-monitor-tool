from flask import Flask, request, redirect, url_for, session, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Example: 'admin' or 'user'

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        role = request.form['role']  # Example: 'admin' or 'user'
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        # Debugging statement to check if user was found
        print(f"Trying to log in user: {username}")
        if user:
            print(f"User found: {user.username}")
            if check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['role'] = user.role
                print(f"Logged in user: {session['user_id']}, role: {session['role']}")
                flash('Login successful!')
                return redirect(url_for('home'))
            else:
                print("Password mismatch")
        else:
            print("User not found")
        
        flash('Login failed. Check your credentials.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('You have been logged out.')
    return redirect(url_for('home'))

def requires_role(role):
    def wrapper(func):
        def wrapped_func(*args, **kwargs):
            if session.get('role') != role:
                flash('Access denied.')
                return redirect(url_for('home'))
            return func(*args, **kwargs)
        return wrapped_func
    return wrapper

@app.route('/admin')
@requires_role('admin')
def admin():
    return render_template('admin.html')

if __name__ == '__main__':
    app.run(debug=True)
