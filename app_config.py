from datetime import timedelta
from flask import Flask
from flask_login import LoginManager, UserMixin
import fldr
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://db_user:ghpeworvaozzks@localhost/upb'
# todo: pri pridávani na server odkomentovať, upb musí byť lowercase!
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://dbadmin:ghpeworvaozzks@localhost/UPB'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://dbadmin:ghpeworvaozzks@localhost/upb'
db = SQLAlchemy(app)
# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     storage_uri="memcached://localhost:50001",
#     storage_options={}
# )


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    user_id = db.Column('user_id', db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(255))
    psswd = db.Column(db.String(255))
    salt = db.Column(db.String(255))
    pub = db.Column(db.String(511), default=None)
    priv = db.Column(db.String(2047), default=None)
    is_active = db.Column(db.Boolean, default=True)
    authenticated = db.Column(db.Boolean, default=False)

    def __init__(self, name, email, psswd, salt, private, public):
        self.name = name
        self.email = email
        self.psswd = psswd
        self.salt = salt
        self.pub = public
        self.priv = private

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

    def getUserNameById(id):
        return User.query.get(id).name

    def getIdByUserName(name):
        try:
            return User.query.filter_by(name=name).first().user_id
        except:
            return None

    def getIdByEmail(email):
        try:
            return User.query.filter_by(email=email).first()
        except:
            return None

    def getPublicKey(id):
        return User.query.filter_by(user_id=id).first().pub

    def getPrivateKey(id):
        return User.query.filter_by(user_id=id).first().priv

    def getUserbyId(id):
        try:
            return User.query.filter_by(user_id=id).first()
        except:
            return None

    @login.user_loader
    def load_user(id):
        return User.query.get(int(id))


    def __init__(self, name, email, psswd, salt, private, public):
        self.name = name
        self.email = email
        self.psswd = psswd
        self.salt = salt
        self.pub = public
        self.priv = private
    
class Message(db.Model):
    message_id = db.Column('message_id', db.Integer, primary_key=True)
    sender_ID = db.Column(db.Integer)
    recipient_ID = db.Column(db.Integer)
    messageLocation = db.Column(db.String(255))


    @staticmethod
    def create(sender_ID, recipient_ID, messageLocation):  # create new user
        new_message = Message(sender_ID, recipient_ID, messageLocation)
        db.session.add(new_message)
        db.session.commit()


    def get_id(self):
        return self.user_id



    def __init__(self, sender_ID, recipient_ID, messageLocation):
        self.sender_ID = sender_ID
        self.recipient_ID = recipient_ID
        self.messageLocation = messageLocation


def selectMessages(user_ID):
    #s = select(Message.recipient_ID).where(Message.sender_ID == user_ID)
    s = Message.query.filter((Message.sender_ID==user_ID) |(Message.recipient_ID==user_ID)).all()
    #s += Message.query.filter_by(recipient_ID=1).all()
    
    return s
