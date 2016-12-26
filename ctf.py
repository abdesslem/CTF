__author__ = "ask3m"
__date__ = "$Oct 21, 2015 3:12:16 PM$"

from flask import Flask, render_template, redirect, url_for, flash, session, abort, request
from flask_security import Security
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bootstrap import Bootstrap
from flask_admin import Admin
from flask_mail import Mail
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers
from flask_sqlalchemy import SQLAlchemy
from flask.ext.mail import Message
from itsdangerous import URLSafeTimedSerializer
from forms import LoginForm, RegistrationForm
from sqlalchemy import desc
import datetime
import models

app = Flask('__name__')
app.config.from_object('config')
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
mail = Mail(app)
Bootstrap(app)
admin = Admin(app)

@login_manager.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return models.User.query.get(int(user_id))

@app.route('/')
def index():
    if not current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('login'))
    challenges = models.Challenges.query.all()
    query = db.session.query(models.Challenges.category.distinct().label("category"))
    categories = [row.category for row in query.all()]
    ranking = rank(current_user.username)
    #tasks = Challenges.query.group_by(Challenges.category).all()
    return render_template('index.html', challenges=challenges, categories=categories, ranking=ranking)

@app.route('/rules')
@login_required
def rules():
    return render_template('rules.html')

@app.route('/scoreboard')
@login_required
def scoreboard():
    users = models.User.query.filter(models.User.username!='admin').order_by(desc(models.User.score)).all()
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
    challenge = models.Challenges.query.filter_by(name=challenge_name).first()
    if form.validate_on_submit() and challenge.flag == form.flag.data :
	# Update user's score and solved tasks
	user = models.User.query.filter_by(username=current_user.username).first()
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

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = models.User.query.filter_by(username=form.login.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('register'))
	user = User(username=form.login.data,
                       email=form.email.data,
		       password=form.password.data,
		       school=form.school.data,
		       score='0',
		       solved='')
	db.session.add(user)
	db.session.commit()
	token = generate_confirmation_token(form.email.data)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(form.email.data, subject, html)
        flash('A confirmation email has been sent via email.', 'success')
	return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = models.User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('login'))

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
	user = models.User.query.filter_by(username=form.login.data).first()
	if user is None or not user.verify_password(form.password.data) or not user.confirmed:
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

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

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



# The context processor makes the rank function available to all templates
@app.context_processor
def utility_processor():
    def rank(user_name):
        users = models.User.query.order_by(desc(models.User.score)).all()
        myuser = models.User.query.filter_by(username=user_name).first()
        l = []
        for user in users :
            l.append(user.score)
        return int(l.index(myuser.score)) + 1
    return dict(rank=rank)

def rank(user_name):
    users = models.User.query.order_by(desc(models.User.score)).all()
    myuser = models.User.query.filter_by(username=user_name).first()
    l = []
    for user in users :
        l.append(user.score)
    return int(l.index(myuser.score)) + 1

db.create_all()
#admin.add_view(MyModelView(User, db.session))
#admin.add_view(MyModelView(Challenges, db.session))
if __name__ == '__main__':
    app.run(debug=True)
