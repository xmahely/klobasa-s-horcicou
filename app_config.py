from datetime import timedelta
from flask import Flask
from flask_login import LoginManager, UserMixin
import fldr
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
import encrypt_decrypt as ED
from flask_qrcode import QRcode
from flask_socketio import SocketIO, emit

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
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://dbadmin:ghpeworvaozzks@localhost/UPB'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://dbadmin:ghpeworvaozzks@localhost/upb'
db = SQLAlchemy(app)
qrcode = QRcode(app)
socketio = SocketIO(app, async_mode="threading")

# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     storage_uri="memcached://localhost:50001",
#     storage_options={}
# )
