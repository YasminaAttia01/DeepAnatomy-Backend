from flask import Flask, render_template, url_for, redirect, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(10), nullable=False)
    password = db.Column(db.String(80), nullable=False)

    # Relation one-to-many avec la table UserInterest
    interests = db.relationship('UserInterest', backref='user', lazy=True)

class UserInterest(db.Model):
    idInterest = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topic = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    lab = db.Column(db.String(100), nullable=False)

class InterestForm(FlaskForm):
    topic = SelectField('Select your interest', 
                        choices=[
                            ('Genetic Engineering', 'Genetic Engineering'),
                            ('Urinary System: Kidneys and Bladder', 'Urinary System: Kidneys and Bladder'),
                            ('Immune System: Lymphatic Structures and Functions', 'Immune System: Lymphatic Structures and Functions'),
                            ('Microbiome and Human Health', 'Microbiome and Human Health'),
                            ('Abdominal Anatomy', 'Abdominal Anatomy'),
                            ('Skeletal System: Bone Structure', 'Skeletal System: Bone Structure')
                        ],
                        validators=[InputRequired()])
    
    author = SelectField('Choose your favorite author', 
                         choices=[
                            ('Richard Dawkins', 'Richard Dawkins'),
                            ('Lynn Margulis', 'Lynn Margulis'),
                            ('Nettie Stevens', 'Nettie Stevens'),
                            ('Thomas Hunt Morgan', 'Thomas Hunt Morgan'),
                            ('Alexander Fleming', 'Alexander Fleming'),
                            ('Jane Goodall', 'Jane Goodall')
                         ],
                         validators=[InputRequired()])
    
    lab = SelectField('Choose your favorite research laboratory', 
                      choices=[
                          ('Science Lab', 'Science Lab'),
                          ('Medical Lab', 'Medical Lab'),
                          ('Lab MAGNUS', 'Lab MAGNUS'),
                          ('SCIENCE LABORATOIRE', 'SCIENCE LABORATOIRE'),
                          ('CNRS', 'CNRS')
                      ],
                      validators=[InputRequired()])
    
    submit = SubmitField('Submit')

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[
                        InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Email"})
    role = StringField(validators=[
                       InputRequired(), Length(min=4, max=10)], render_kw={"placeholder": "Role"})
    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError('That email already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('interests'))
        else:
            form.password.errors.append("Incorrect username or password. Please try again.")
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, role=form.role.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/interests', methods=['GET', 'POST'])
@login_required
def interests():
    form = InterestForm()
    if form.validate_on_submit():
        new_interest = UserInterest(
            user_id=current_user.id,
            topic=form.topic.data,
            author=form.author.data,
            lab=form.lab.data
        )
        db.session.add(new_interest)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('interests.html', form=form)

@app.route('/api/logout', methods=['POST'])
def api_logout():
    logout_user()
    return jsonify({"message": "Logout successful"}), 200

if __name__ == "__main__":
    app.run(debug=True)
