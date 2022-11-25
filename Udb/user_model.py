from flask_login import UserMixin

from Udb.timeTicket_model import timeTicket
from Udb.ticket_model import ticket
from app_config import db, login


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
    timeTicket = db.Column('timeTicket_id', db.Integer, db.ForeignKey(timeTicket.ticket_id),default = None)
    ticket = db.Column('ticket_id',db.Integer, db.ForeignKey(ticket.ticket_id), default= None)
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