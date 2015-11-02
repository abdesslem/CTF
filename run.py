__author__ = "ask3m"
__date__ = "$Oct 21, 2015 3:12:16 PM$"

from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask.ext.login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask.ext.bootstrap import Bootstrap
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

from app import app
app.run(debug=True)
