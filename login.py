from flask import Flask
from flask.ext.login import LoginManager
from pymongo import MongoClient
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from flask import request, redirect, render_template, url_for, flash
from flask.ext.login import login_user, logout_user, login_required
from werkzeug.security import check_password_hash


class User():
    def __init__(self,username):
        self.username = username
        self.password = None

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.username

    @staticmethod
    def validate_login(password_hash, password):
        return check_password_hash(password_hash, password)

#Defining the LoginForm class
class LoginForm(Form):

    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


app = Flask(__name__)
#-----All Endpoints
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        print "POST REQ"
        user = app.config['USERS_COLLECTION'].find_one({"_id": form.username.data})
        print "USER:--------------  " + form.username.data
        if user and User.validate_login(user['password'], form.password.data):
            user_obj = User(user['_id'])
            login_user(user_obj)
            flash("Logged in successfully!", category='success')
            return '1'
        flash("Wrong username or password!", category='error')
    return '0'

@app.route('/logout')
def logout():
    logout_user()
    return '1'


def load_user(username):
    u = app.config['USERS_COLLECTION'].find_one({"_id": username})
    if not u:
        return None
    return User(u['_id'])

if __name__ == '__main__':

    app.run('0.0.0.0',9000,debug = True)
