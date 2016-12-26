from flask_wtf import Form
from flask_wtf.recaptcha import RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import Required, Length, EqualTo, Email

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
    recaptcha = RecaptchaField()
    submit = SubmitField('Register')
