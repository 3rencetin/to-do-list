from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_COOKIE_SECURE'] = True 
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

class TodoItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<TodoItem {self.id}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='scrypt')

        new_user = User(username=username, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except Exception as e:
            print(e)
            return 'There was an issue creating your account'

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    todo_items = TodoItem.query.all()
    return render_template('index.html', todo_items=todo_items)

@app.route('/add_item', methods=['POST'])
@login_required
def add_item():
    content = request.form['content']
    new_item = TodoItem(content=content)

    try:
        db.session.add(new_item)
        db.session.commit()
        return redirect(url_for('index'))
    except Exception as e:
        print(e)
        return 'There was an issue adding your item'

@app.route('/delete/<int:id>')
@login_required
def delete_item(id):
    item_to_delete = TodoItem.query.get_or_404(id)

    try:
        db.session.delete(item_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except Exception as e:
        print(e)
        return 'There was a problem deleting that item'

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_item(id):
    item = TodoItem.query.get_or_404(id)

    if request.method == 'POST':
        item.content = request.form['content']

        try:
            db.session.commit()
            return redirect(url_for('index'))
        except Exception as e:
            print(e)
            return 'There was an issue updating your item'
    else:
        return render_template('edit_item.html', item=item)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Veritabanı tablolarını oluşturur
    app.run(ssl_context='adhoc')  # HTTPS zorunluluğu için self-signed sertifika
