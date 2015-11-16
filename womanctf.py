__author__ = "ask3m"
__date__ = "$Oct 21, 2015 3:12:16 PM$"

import os
import base64
from flask import Flask, render_template, redirect, url_for, flash, session, abort, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_security import Security
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask.ext.login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask.ext.bootstrap import Bootstrap
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import Required, Length, EqualTo, Email
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers
import datetime
app = Flask('__name__')
app.config.from_object('config')
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
admin = Admin(app)



# Create customized model view class
class MyModelView(sqla.ModelView):

    def is_accessible(self):
        if not current_user.is_active() or not current_user.is_authenticated():
            return False

        if current_user.username == "test":
            return True

        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated():
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(120))
    school = db.Column(db.String(120))
    score = db.Column(db.String(20))
    solved = db.Column(db.String(400))
    lastSubmit = db.Column(db.DateTime)
    #timestamp=datetime.datetime.utcnow()
    #def __init__(self, **kwargs):
    #    super(User, self).__init__(**kwargs)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username

class Challenges(db.Model):
    __tablename__ = 'challenges'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    category = db.Column(db.String(80))
    info = db.Column(db.String(800))
    score = db.Column(db.String(20))
    flag = db.Column(db.String(40))

    def __repr__(self):
        return '<Challenges %r>' % self.name

@login_manager.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


# The context processor makes the rank function available to all templates
@app.context_processor
def utility_processor():
    def rank(user_name):
        users = User.query.order_by(desc(User.score)).all()
        myuser = User.query.filter_by(username=user_name).first()
        l = []
        for user in users :
            l.append(user.score)
        return int(l.index(myuser.score)) + 1
    return dict(rank=rank)

def rank(user_name):
    users = User.query.order_by(desc(User.score)).all()
    myuser = User.query.filter_by(username=user_name).first()
    l = []
    for user in users :
        l.append(user.score)
    return int(l.index(myuser.score)) + 1

class LoginForm(Form):
    login = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Login')

class FlagForm(Form):
    flag = StringField('The Flag', validators=[Required(), Length(1, 64)])
    submit = SubmitField('Send')

class RegistrationForm(Form):
    login = StringField('Username', validators=[Required()])
    email = StringField('Email', validators=[Required(), Email()])
    password = PasswordField('Password', validators=[Required()])
    password_again = PasswordField('Password again',
                                   validators=[Required(), EqualTo('password')])
    school = StringField()
    submit = SubmitField('Register')

@app.route('/')
def index():
    if not current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('login'))
    challenges = Challenges.query.all()
    query = db.session.query(Challenges.category.distinct().label("category"))
    categories = [row.category for row in query.all()]
    ranking = rank(current_user.username)
    #tasks = Challenges.query.group_by(Challenges.category).all()
    return render_template('index.html', challenges=challenges, categories=categories, ranking=ranking)

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
	user = User(username=form.login.data,
                       email=form.email.data,
		       password=form.password.data,
		       school=form.school.data,
		       score='0',
		       solved='')
	db.session.add(user)
	db.session.commit()
	flash('Thank you for registration')
	return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        # Login and validate the user.
        # user should be an instance of your `User` class
	user = User.query.filter_by(username=form.login.data).first()
	if user is None or not user.verify_password(form.password.data):
	    flash('Invalid username or password')
	    return redirect(url_for('login'))
        login_user(user)
        flash('Logged in successfully.')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """Logout the current user."""
    logout_user()
    return redirect(url_for('index'))

@app.route('/rules')
@login_required
def rules():
    return render_template('rules.html')

@app.route('/scoreboard')
@login_required
def scoreboard():
    users = User.query.filter(User.username!='admin').order_by(desc(User.score)).all()
    winners = []
    temps = []
    for user in users :
        if rank(user.username) == 1 :
	    winners.append(user)
            temps.append(user.lastSubmit)
    winnertime = min(temps)
    return render_template('scoreboard.html', users=users, winnertime=winnertime)

@app.route('/challenges/<challenge_name>',methods=["GET","POST"])
@login_required
def challenges(challenge_name):
    form = FlagForm()
    challenge = Challenges.query.filter_by(name=challenge_name).first()
    if form.validate_on_submit() and challenge.flag == form.flag.data :
	# Update user's score and solved tasks
	user = User.query.filter_by(username=current_user.username).first()
	user.score = str(int(user.score) + int(challenge.score))
	user.solved = user.solved + ',' + challenge.name
	user.lastSubmit = datetime.datetime.utcnow()
	db.session.commit()
        flash('Good Job Valid Flag')
        return redirect(url_for('index'))
    elif form.validate_on_submit() and challenge.flag != form.flag.data :
        flash('Wrong Flag')
        return render_template('challenges.html',form=form, challenge=challenge )
    return render_template('challenges.html',form=form, challenge=challenge )

db.create_all()
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Challenges, db.session))
if __name__ == '__main__':
    app.run(debug=True)
