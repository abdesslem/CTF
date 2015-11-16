import os

SECRET_KEY = 'p4ssw0rd_c0d3'
SECURITY_PASSWORD_SALT = 'my_s3cUr3_s4lt'
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')

# mail settings
MAIL_SERVER = 'smtp.googlemail.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True

# gmail authentication
MAIL_USERNAME = os.environ['APP_MAIL_USERNAME']
MAIL_PASSWORD = os.environ['APP_MAIL_PASSWORD']


# mail accounts
MAIL_DEFAULT_SENDER = 'amriabdesslem@gmail.com'

