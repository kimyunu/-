from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, login_user, logout_user, UserMixin, login_required

app = Flask(__name__)
app.secret_key = '🔐yooncar-ultra-secret🔐'

login_manager = LoginManager()
login_manager.init_app(app)

# 유저 모델
class User(UserMixin):
    def __init__(self, id):
        self.id = id

users = {"admin": User("admin")}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == 'admin' and request.form['password'] == '2050secure':
            login_user(users['admin'])
            return redirect('/dashboard')
    return '''
        <form method="post">
            <input name="username" placeholder="Username">
            <input name="password" placeholder="Password" type="password">
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/dashboard')
@login_required
def dashboard():
    return "🚨 Welcome to YoonCar Secure Dashboard. Access level: TOP SECRET"

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # HTTPS
