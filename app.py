from flask import Flask, render_template, redirect, url_for, flash, request, get_flashed_messages
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SESSION_PERMANENT'] = True


# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# SQLAlchemy setup
db = SQLAlchemy(app)

# Flask-Bcrypt setup
bcrypt = Bcrypt(app)

# User class for Flask-Login
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    roles = db.relationship('Role', secondary='user_roles', backref=db.backref('users', lazy='dynamic'))
        
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

# Many-to-Many relationship table between users and roles
user_roles = db.Table('user_roles',
                      db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                      db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
                      )

# WTForms for user registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('student', 'Student'), ('librarian', 'Librarian'), ('head_librarian', 'Head Librarian')], validators=[DataRequired()])
    submit = SubmitField('Register')

# WTForms for user login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Routes
@app.route('/')
def home():
    # Retrieve flashed messages
    messages = get_flashed_messages(with_categories=True)
    
    return render_template('index.html', messages=messages)

@app.route('/userpage', methods=['GET', 'POST'])
def userpage():
    # Retrieve flashed messages
    messages = get_flashed_messages(with_categories=True)

    return render_template('userpage.html', messages=messages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if the username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('register'))
        
        # Hashing using Bcrypt
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # Create a new user
        new_user = User(username=form.username.data, password=hashed_password)
        
        # Assign roles to the user based on the form selection
        if form.role.data:
            role_name = form.role.data
            role = Role.query.filter_by(name=role_name).first()
            if role is None:
                # Handle the case where the role is not found
                flash('Invalid role selected. Please choose a valid role.', 'danger')
                flash(f'Role "{role_name}" not found in the database.', 'danger')
                return redirect(url_for('register'))
            new_user.roles.append(role)
        
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('userpage'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

# Route for students to borrow books
@app.route('/borrow', methods=['GET', 'POST'])
@login_required
def borrow():
    if any(role.name in ['student', 'librarian', 'head_librarian'] for role in current_user.roles):
        # Logic for students to borrow books
        if request.method == 'POST':
            # Handle book borrowing logic
            flash('Book borrowed successfully!', 'success')
        return render_template('borrow.html')
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('userpage'))

# Route for librarians to manage books
@app.route('/manage_books', methods=['GET', 'POST'])
@login_required
def manage_books():
    if any(role.name in ['librarian', 'head_librarian'] for role in current_user.roles):
        # Logic for librarians to manage books
        if request.method == 'POST':
            # Handle book management logic
            flash('Book management successful!', 'success')
        return render_template('manage_books.html')
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('userpage'))

# Route for admin operations
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if 'head_librarian' in [role.name for role in current_user.roles]:
        # Get the list of users
        users = User.query.all()
        
        if request.method == 'POST':
            operation = request.form.get('operation')
            if operation == 'add_book':
                # Logic for adding a book
                flash('Book added successfully!', 'success')
            elif operation == 'remove_book':
                # Logic for removing a book
                flash('Book removed successfully!', 'success')
            elif operation == 'delete_user':
                user_id = request.form.get('user')
                user_to_delete = User.query.get(user_id)

                if user_to_delete:
                    # Logic for deleting a user
                    db.session.delete(user_to_delete)
                    db.session.commit()
                    flash('User deleted successfully!', 'success')
                else:
                    flash('User not found.', 'danger')
            # Add more conditions for other operations

        return render_template('admin.html', users=users, selected_operation=request.form.get('operation', ''))
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('userpage'))

# Callback to reload the user object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == '__main__':
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Add initial roles if they don't exist
        roles = ['student', 'librarian', 'head_librarian']
        for role_name in roles:
            role = Role.query.filter_by(name=role_name).first()
            if role is None:
                # If role not found, then add to database
                role = Role(name=role_name)
                db.session.add(role)

        # Print debug information
        print("Roles in the database:")
        print(Role.query.all())

        # Commit changes
        db.session.commit()
    app.run(host='0.0.0.0', debug=True)

    