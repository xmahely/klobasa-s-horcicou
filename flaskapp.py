import os
import time

from flask import redirect, url_for, render_template, request, flash, send_file, session
from werkzeug.exceptions import RequestEntityTooLarge
from flask_login import current_user, login_user, logout_user, login_required
import fldr
import data_handler
import encrypt_decrypt as ED
from app_config import app, db, login, turbo
from Udb import no_ticket_model, ticket_model
from Udb.message_model import Message
from Udb.user_model import User
from Udb.no_ticket_model import no_ticket
import uuid
from datetime import datetime, timedelta
from pytz import utc
import threading

@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@turbo.user_id
def get_user_id():
    if current_user is None:
        return None
    if current_user.is_authenticated:
        return current_user.user_id
    else:
        return None


with app.app_context():
    # db.drop_all() # toto používať len na premazenia celej db
    db.create_all()
    # no_ticket_model.create_ticket_types()

def get_tickets():
    print(current_user, flush=True)
    ticket_model.tag_inactive_tickets()
    # return ticket_model.get_user_tickets(current_user.user_id)
    return ticket_model.get_user_tickets(1)

@app.context_processor
def inject_load():
    return {'tickets': get_tickets(), 'now': datetime.now().replace(tzinfo=None)}

def update_load():
    with app.app_context():
        while True:
            time.sleep(1)
            turbo.push(turbo.replace(render_template('tickets.html'), 'load_ticket'))


@app.before_first_request
def before_first_request():
    print(current_user, flush=True)
    threading.Thread(target=update_load).start()


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect('homepage')
    else:
        return redirect('login')


@app.route("/cpkNkWrXsl/buy/<int:ticket_type>")
@login_required
def buy_ticket(ticket_type):
    if current_user.is_authenticated:
        ticket_model.create_new(current_user.user_id, ticket_type)
        return redirect(url_for('user'))
    else:
        return render_template('login.html')


@app.route("/buyTickets")
@login_required
def buy_tickets():
    if current_user.is_authenticated:
        return render_template('buytickets.html', tickets=no_ticket_model.get_tickets())
    else:
        return render_template('login.html')


@app.route("/buySeasonTickets")
@login_required
def buy_seasontickets():
    if current_user.is_authenticated:
        return render_template('buyseasontickets.html', tickets=no_ticket_model.get_season_tickets())
    else:
        return render_template('login.html')

@login_required
@app.route("/homepage")
def homepage():
    return render_template("index.html", username=current_user.name)


@app.route("/register", methods=["POST", "GET"])
# @limiter.limit("1/second") TODO toto by malo zabranit ddos akurat to nejde uplne dobre
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["password2"]
        existing_user_username = User.getIdByUserName(username)
        existing_email = User.getIdByEmail(email)
        check = ED.psswd_check(password, confirm)
        if existing_user_username:
            flash('This username already exists, try a new one!')
        elif existing_email:
            flash('This email address is already in use!')
        elif check == 1:
            flash('Password too weak')
        elif check == -1:
            flash('Passwords do not match')
        else:
            psswd, salt = ED.psswd_hash(password)
            private, public = ED.generate_rsa_pair()
            new_user = User(username, email, psswd, salt, private.encode(), public)
            db.session.add(new_user)
            try:
                db.session.commit()
                path = "/home/Users/" + username
                os.mkdir(path)
                make_key_files(username, private, public)
                # TODO toto nech neni warning
                # namalo by sa stat ze existuje uz folder kedze username je unique
                flash('Registration successful', '')
                return render_template('register.html')
            except Exception as e:
                return render_template("register.html")
    return render_template("register.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        if 'timeout' in session:
            if session.get('timeout').replace(tzinfo=utc) > datetime.now().replace(tzinfo=utc):
                flash(f"You are locked out. You can log in after "
                      f"{session.get('timeout').strftime('%d.%m.%Y %H:%M:%S')}.")
                return redirect(request.url)
        if 'timeout_count' not in session:
            session['timeout_count'] = 1
        if 'counter' not in session:
            session['counter'] = 0
        session.permanent = True
        user = request.form["username"].strip()
        password = request.form["password"]
        u = User.query.filter_by(name=user).first()
        try:
            if ED.authenticate(u.salt, password.strip(), u.psswd) == 0:
                if 'timeout' in session:
                    timeout = session.get('timeout')
                    session.pop('timeout', None)
                    if timeout.replace(tzinfo=utc) > datetime.now().replace(tzinfo=utc):
                        flash(f"You are locked out. You can log in after "
                              f"{session.get('timeout').strftime('%d.%m.%Y %H:%M:%S')}.")
                        return redirect(request.url)
                login_user(u)
                session.pop('counter', None)
                session.pop('timeout_count', None)
                return redirect(url_for('homepage'))
            else:
                flash(f"The username or password is incorrect!")
                if 'counter' in session:
                    session['counter'] = session.get('counter') + 1
                if session.get('counter') > 3:
                    if 'timeout' not in session:
                        session['timeout'] = datetime.now().replace(tzinfo=utc)
                    session['timeout_count'] = session.get('timeout_count') * 6
                    if 'timeout' not in session:
                        session['timeout'] = 0
                    session['timeout'] = session.get('timeout') + timedelta(seconds=session.get('timeout_count'))
                    flash(f"You have tried to log in {session.get('counter')} times. You can log in after "
                          f"{session.get('timeout').strftime('%d.%m.%Y %H:%M:%S')}.")
                return redirect(request.url)
        except Exception:
            flash(f"The username does not exist!")
            return redirect(request.url)
    else:
        if current_user.is_authenticated:
            return render_template('user_page.html', username=current_user.name, reload=False)
        return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/user")
def user():
    if current_user.is_authenticated:
        return render_template("user_page.html", username=current_user.name, email=current_user.email,
                               p_key=current_user.pub,
                               path_public_key=fldr.UPLOAD_FOLDER + current_user.name + "/id_rsa_public.pub",
                               path_private_key=fldr.UPLOAD_FOLDER + current_user.name + "/id_rsa.pem", reload=False)
    else:
        return redirect(url_for("login"))


def allowed_file(file, extension):
    if len(file.split('.')) > 2:
        return False
    return '.' in file and file.rsplit('.', 1)[1].lower() == extension


@app.route("/download/<path:path>")
def download_file(path):
    # todo: pri pridávani na server odkomentovať, musí tam byť /
    return send_file("/" + path, as_attachment=True)
    # return send_file(path, as_attachment=True)


@app.route("/download/documentation")
def download_documentation():
    return send_file("documentation.pdf", as_attachment=True)


@app.route("/download/enc_tool")
def download_enc_tool():
    return send_file("enc_tool.py", as_attachment=True)


@app.errorhandler(401)
def unauthorized(e):
    return render_template("401.html")


@app.route("/encrypt", methods=["POST", "GET"])
@login_required
def encrypt():
    if request.method == "POST":
        try:
            if 'text_file' not in request.files or 'public_key' not in request.files:
                flash('Corrupted text file or public key')
                return redirect(request.url)
        except RequestEntityTooLarge:
            flash('Key or file is too big! Must be less than 1GB.')
            return redirect(request.url)

        text_file = request.files['text_file']
        public_key = request.files['public_key']
        if not allowed_file(public_key.filename, 'pub') and not allowed_file(text_file.filename, 'txt'):
            flash('Wrong extension for public key and file. Should be .pub for public key and .txt for file.')
            return redirect(request.url)
        elif not allowed_file(public_key.filename, 'pub'):
            flash('Wrong extension for public key. Should be .pub.')
            return redirect(request.url)
        elif not allowed_file(text_file.filename, 'txt'):
            flash('Wrong extension for file. Should be .txt')
            return redirect(request.url)

        text_file_string = data_handler.read_file(text_file, True)

        if not text_file_string:
            flash('Text file must not be empty !')
            return redirect(request.url)
        public_key_string = data_handler.read_public_key(public_key, True)
        if not public_key_string:
            flash('Key has to have correct format !')
            return redirect(request.url)
        else:
            encrypted_text_string = ED.encrypt_file(text_file_string, public_key_string)
            path = os.path.join(fldr.UPLOAD_FOLDER, 'encrypted.txt')
            f = open(path, "w+")
            f.write(encrypted_text_string)
            f.close()
            return render_template('download.html', header="Encrypted file", path_download=path)
    else:
        return render_template("encrypt.html")


@app.route("/decrypt", methods=["POST", "GET"])
@login_required
def decrypt():
    if request.method == "POST":
        try:
            if 'text_file' not in request.files or 'private_key' not in request.files:
                flash('Corrupted text file or private key')
                return redirect(request.url)
        except RequestEntityTooLarge:
            flash('Key or file is too big! Must be less than 1GB.')
            return redirect(request.url)

        text_file = request.files['text_file']
        private_key = request.files['private_key']
        if not allowed_file(private_key.filename, 'pem') and not allowed_file(text_file.filename, 'txt'):
            flash('Wrong extension for private key and file. Should be .pem for public key and .txt for file.')
            return redirect(request.url)
        elif not allowed_file(private_key.filename, 'pem'):
            flash('Wrong extension for public key. Should be .pem.')
            return redirect(request.url)
        elif not allowed_file(text_file.filename, 'txt'):
            flash('Wrong extension for file. Should be .txt')
            return redirect(request.url)

        text_file_string = data_handler.read_file(text_file, True)
        if not text_file_string:
            flash('Text file must not be empty !')
            return redirect(request.url)
        private_key_string = data_handler.read_private_key(private_key, True)
        if not private_key_string:
            flash('Key has to have correct format !')
            return redirect(request.url)
        else:
            decrypted_text_string = ED.decrypt_file(text_file_string, private_key_string)
            path = os.path.join(fldr.UPLOAD_FOLDER, 'decrypted.txt')
            f = open(path, "w+")
            f.write(decrypted_text_string)
            f.close()
            return render_template('download.html', header="Decrypted file", path_download=path)
    else:
        return render_template("decrypt.html")


def make_key_files(username, private_key, public_key):
    if not os.path.isdir(os.path.join(fldr.UPLOAD_FOLDER, username)):
        os.mkdir(os.path.join(fldr.UPLOAD_FOLDER, username))
    path_public_key = os.path.join(fldr.UPLOAD_FOLDER, username, 'id_rsa_public.pub')
    path_private_key = os.path.join(fldr.UPLOAD_FOLDER, username, 'id_rsa.pem')
    f = open(path_private_key, "w+")
    f.write(private_key)
    f.close()
    f = open(path_public_key, "w+")
    f.write(public_key)
    f.close()
    return path_public_key, path_private_key


@app.route("/generate", methods=["POST", "GET"])
@login_required
def generate_keys():
    if request.method == "POST":
        private_key, public_key = ED.generate_rsa_pair()
        path_public_key, path_private_key = make_key_files(current_user.name, private_key, public_key)
        try:
            u = User.getUserbyId(current_user.user_id)
            if u is None:
                raise Exception()
            u.priv = private_key.encode()
            u.pub = public_key
            db.session.commit()
            return render_template('download2.html', header="Generated keys", path_public_key=path_public_key,
                                   path_private_key=path_private_key)
        except Exception:
            flash("Unexpected error")
            return redirect(request.url)
    else:
        return render_template("generate.html")


@app.route("/nope")
def nope():
    return "I give up :("


# <input class="textarea form-control" type="textarea" id="text" name="text" rows="4">
@app.route("/chat/", methods=["POST", "GET"], defaults={'chatterID': 0})
@app.route("/chat/<int:chatterID>", methods=["POST", "GET"])
@login_required
def chat(chatterID=0):
    # print(chatterID)
    if request.method == "POST":

        message = request.form.get('message', "error")
        newUser = request.form.get('newUser', chatterID)
        if (newUser != chatterID and (User.getIdByUserName(newUser) == None)) or (
                User.getIdByUserName(newUser) == current_user.user_id):
            json = getJSON(current_user.user_id)
            return render_template("chat.html", messages=json, displayUser=chatterID)
        if (message == "error" and newUser != chatterID):
            message = "Hello"
            newUser = User.getIdByUserName(newUser)
        # Moving forward code
        # print("TO: ",newUser)
        # print("FROM: ",current_user.user_id)

        public_key_path = ("tmp/public_key.pub")

        text_file_string = message

        public_key_string = data_handler.read_public_key3(User.getPublicKey(newUser))
        # print(public_key_string)
        if not public_key_string:
            flash('Key has to have correct format !')
            return redirect(request.url)
        else:
            encrypted_text_string = ED.encrypt_file(text_file_string, public_key_string)
            unique_filename = str(uuid.uuid4())
            path = os.path.join(fldr.UPLOAD_FOLDER, 'messages', unique_filename)
            f = open(path, "w+")
            f.write(encrypted_text_string)
            f.close()

        Message.create(current_user.user_id, newUser, path)
        json = getJSON(current_user.user_id)
        # print(selectMessages(1))
        return render_template("chat.html", messages=json, displayUser=chatterID)
    else:

        json = getJSON(current_user.user_id)
        # print(selectMessages(1))
        return render_template("chat.html", messages=json, displayUser=chatterID)


def getJSON(user_ID):
    struct = {}
    try:
        messages = Message.selectMessages(user_ID)
        # print(messages)
        for message in messages:

            # private_key_path = ("tmp/private_key.pem")
            # private_key_string = data_handler.read_private_key2(private_key_path)
            private_key_string = data_handler.read_private_key3(User.getPrivateKey(message.recipient_ID))

            fp = open(message.messageLocation, 'r')
            message_string = fp.read()

            fp.close()
            decrypted_text_string = ED.decrypt_file(message_string, private_key_string)
            # print(message.recipient_ID)
            if (message.sender_ID == user_ID):
                # print(message.messageLocation)
                struct.setdefault(message.recipient_ID, []).append(
                    tuple((User.getUserNameById(message.sender_ID), decrypted_text_string)))
            if (message.recipient_ID == user_ID):
                # print(message.messageLocation)
                struct.setdefault(message.sender_ID, []).append(
                    tuple((User.getUserNameById(message.sender_ID), decrypted_text_string)))

        # print(struct)
        # print(jsonData)
        return struct
    except:
        print("OH MY LAWRD")
        return struct


@app.template_global()
def getUserName(id):
    return User.getUserNameById(id)

# TODO deactivate user .. delete from Udb and delete system folder


if __name__ == "__main__":
    app.jinja_env.globals.update(getUserName=getUserName)
    with app.app_context():
        db.create_all()

    app.debug = True
    app.run(host='0.0.0.0')
