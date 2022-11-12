from datetime import timedelta
from flask import Flask
from flask_login import LoginManager, UserMixin
import fldr
from flask_sqlalchemy import SQLAlchemy
import encrypt_decrypt as ED

app = Flask(__name__)
login = LoginManager(app)
login.session_protection = 'strong'
login.init_app(app)
app.config['UPLOAD_FOLDER'] = fldr.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024
app.secret_key = 'U1a2C&5f#kfu#8kU8W5A'
app.permanent_session_lifetime = timedelta(minutes=30)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://db_user:ghpeworvaozzks@localhost/upb'
# todo: pri pridávani na server odkomentovať, upb musí byť lowercase!
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://dbadmin:ghpeworvaozzks@localhost/upb'
db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    user_id = db.Column('user_id', db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(255))
    psswd = db.Column(db.String(255))
    salt = db.Column(db.String(255))
    pub = db.Column(db.String(255), default=None)
    priv = db.Column(db.String(255), default=None)
    is_active = db.Column(db.Boolean, default=True)
    authenticated = db.Column(db.Boolean, default=False)

    def __init__(self, name, email, psswd, salt):
        self.name = name
        self.email = email
        self.psswd = psswd
        self.salt = salt
        self.pub = None
        self.priv = None

    def change_keys(self, private, public):
        self.priv = private.encode()
        self.pub = public

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return self.is_active

    def get_id(self):
        return str(self.user_id)

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False
