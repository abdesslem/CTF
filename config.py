import os

SECRET_KEY = 'p4ssw0rd_c0d3'
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')

