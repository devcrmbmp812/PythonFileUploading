from flask import Blueprint, request, render_template, flash, redirect, url_for
from flask_login import login_required, login_user, logout_user, current_user
from wtforms import Form, StringField, PasswordField, validators

from webapp import User, bcrypt, db, required_roles

user = Blueprint('user', __name__)


class LoginForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password ', [validators.DataRequired()])


class SignupForm(Form):
    username = StringField('Username ', [validators.DataRequired(), validators.Length(min=3, max=30)])
    password = PasswordField('Password ', [validators.DataRequired(), validators.Length(min=6, max=25),
                                           validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password ')


class ChangePasswordForm(Form):
    old = PasswordField('Old password ', [validators.DataRequired()])
    new = PasswordField('New password ', [validators.DataRequired(), validators.Length(min=6, max=25),
                                          validators.EqualTo('repeated', message='Passwords must match')])
    repeated = PasswordField('Repeat password ')


@user.route('/signup', methods=['POST', 'GET'])
def signup():
    form = SignupForm(request.form)
    if not current_user.is_authenticated:
        if request.method == 'POST' and form.validate():
            user = User(
                username=form.username.data,
                password=form.password.data,
                role=None
            )
            check_user = User.query.filter_by(username=user.username).first()
            if not check_user:
                db.session.add(user)
                db.session.commit()
                flash('Successful created a new user. You can login now.')
                return redirect(url_for('user.login'))
            else:
                flash('User already exists. Try another username')
                return render_template('signup.html', form=form)
        return render_template('signup.html', form=form)
    else:
        flash('You are already logged in. You need to logout first.')
        return redirect(url_for('home'))


@user.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm(request.form)
    if not current_user.is_authenticated:
        if request.method == 'POST' and form.validate():
            user = User.query.filter_by(username=form.username.data).first()
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=True)
                next = request.args.get('next')
                flash('You were logged in.')
                if next:
                    return redirect(next)
                else:
                    return redirect(url_for('home'))
            else:
                error = 'Invalid username or password.'
        return render_template('login.html', form=form, error=error)
    else:
        flash('You are already logged in. You need to logout first.')
        return redirect(url_for('home'))


@login_required
@user.route('/logout', methods=['GET'])
def logout():
    logout_user()
    flash('You were just logged out.')
    return redirect(url_for('user.login'))


@user.route("/changePassword", methods=['GET', 'POST'])
@login_required
# @required_roles('admin')
def changePassword():
    error = None
    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        old = form.old.data
        new = form.new.data
        repeated = form.repeated.data
        user = User.query.filter_by(username=current_user.username).first()
        if old and new and repeated and user:
            if new == repeated and not bcrypt.check_password_hash(user.password, new):
                new_crypted = bcrypt.generate_password_hash(new)
                user.password = new_crypted
                db.session.commit()
                flash('Successful: Changed password for user %s' % (user.username), )
            else:
                flash('New password and repeated password are not the same or new password equals the old one.')
        else:
            flash('You havent filled out all required fields.')
    return render_template('password.html', form=form, error=error)
