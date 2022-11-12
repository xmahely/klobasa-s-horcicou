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
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://dbadmin:ghpeworvaozzks@localhost/UPB'

login.init_app(app)
db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    user_id = db.Column('user_id', db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(255))
    psswd = db.Column(db.String(255))
    salt = db.Column(db.String(255))
    pub = db.Column(db.String(255))
    priv = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)

    @staticmethod
    def change_keys(self, private, public):
        self.priv = private.encode()
        self.pub = public


    @staticmethod
    def create(name, email, psswd):  # create new user
        psswd, salt = ED.psswd_hash(psswd)
        private, public = ED.generate_rsa_pair()
        new_user = User(name=name, email=email, psswd=psswd, salt=salt, priv=private.encode(), pub=public)
        db.session.add(new_user)
        db.session.commit()

    def is_authenticated(self):
        return self.is_active

    def get_id(self):
        return self.user_id

    @login.user_loader
    def load_user(id):
        return User.query.get(int(id))

    def __init__(self, name, email, psswd, salt, priv, pub):
        self.name = name
        self.email = email
        self.psswd = psswd
        self.salt = salt
        self.priv = priv
        self.pub = pub

