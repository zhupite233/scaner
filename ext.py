from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_principal import Principal
from flask_login import LoginManager
from make_celery import make_celery

app = Flask(__name__, static_folder='web/static',)
celery = make_celery(app)

db = SQLAlchemy()
login_manager = LoginManager()
principal = Principal(app=None, use_sessions=True, skip_static=True)