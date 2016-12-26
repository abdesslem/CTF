from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import ctf


class User(UserMixin, ctf.db.Model):
    __tablename__ = 'users'
    id = ctf.db.Column(ctf.db.Integer, primary_key=True)
    username = ctf.db.Column(ctf.db.String(80), unique=True)
    email = ctf.db.Column(ctf.db.String(80))
    password_hash = ctf.db.Column(ctf.db.String(120))
    school = ctf.db.Column(ctf.db.String(120))
    score = ctf.db.Column(ctf.db.String(20))
    solved = ctf.db.Column(ctf.db.String(400))
    lastSubmit = ctf.db.Column(ctf.db.DateTime)
    confirmed = ctf.db.Column(ctf.db.Boolean, nullable=False, default=False)
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

class Challenges(ctf.db.Model):
    __tablename__ = 'challenges'
    id = ctf.db.Column(ctf.db.Integer, primary_key=True)
    name = ctf.db.Column(ctf.db.String(80), unique=True)
    category = ctf.db.Column(ctf.db.String(80))
    info = ctf.db.Column(ctf.db.String(800))
    score = ctf.db.Column(ctf.db.String(20))
    flag = ctf.db.Column(ctf.db.String(40))

    def __repr__(self):
        return '<Challenges %r>' % self.name
