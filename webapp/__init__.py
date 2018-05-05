from flask import Flask, render_template, redirect, request, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, current_user, UserMixin
import os
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = str(os.urandom(24))
app.config['SESSION_COOKIE_SECURE'] = True

bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///webapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "user.login"

db = SQLAlchemy(app)

from webapp.model import User

db.create_all()


def required_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            error = None
            if current_user.role not in roles:
                error = 'You have not the permission to do that.'
                return redirect(url_for('home'))
            return f(*args, **kwargs)

        return wrapped

    return wrapper


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.after_request
def remove_if_invalid(response):
    if "__invalidate__" in session:
        response.delete_cookie(app.session_cookie_name)
    return response


from webapp.user.routes import user

app.register_blueprint(user)


@app.route('/', methods=['GET'])
@login_required
def home():
    return render_template('index.html')
