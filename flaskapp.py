import os
from flask import Flask, redirect, url_for, render_template, request, flash, send_file, session
from werkzeug.exceptions import RequestEntityTooLarge
from flask_login import current_user, login_user, logout_user, login_required
import fldr
import data_handler
import encrypt_decrypt as ED
from app_config import app, db, User, Message, selectMessages
import uuid
import json


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        if 'timeout' not in session:  # cas medzi prihlaseniami
            session['timeout'] = 0
        if 'counter' not in session:
            session['counter'] = 0
        session.permanent = True
        user = request.form["username"].strip()
        password = request.form["password"]
        u = User.query.filter_by(name=user).first()
        # TODO odpocitavanie kedy povoli dalsi pokus o prihlasenie
        try:
            if ED.authenticate(u.salt, password.strip(), u.psswd) == 0:
                login_user(u)
                return redirect(url_for("user"))
            else:
                if 'counter' in session:
                    session['counter'] = session.get('counter') + 1
                if session.get('counter') > 3:
                    session.pop('counter', None)
                    session['timeout'] = session.get('timeout') + 10
                return render_template("login.html")
        except Exception:
            return render_template("login.html")
    else:
        return render_template("login.html")
        return redirect(url_for("user"))


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/user")
def user():
    if current_user.is_authenticated:
        return render_template("user_page.html", username=current_user)
    else:
        return redirect(url_for("login"))


def allowed_file(file, extension):
    if len(file.split('.')) > 2:
        return False
    return '.' in file and file.rsplit('.', 1)[1].lower() == extension


@app.route("/download/<path:path>")
def download_file(path):
    # return send_file("/"+path, as_attachment=True)
    return send_file(path, as_attachment=True)


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


@app.route("/generate", methods=["POST", "GET"])
#@login_required
def generate_keys():
    if request.method == "POST":
        private_key, public_key = ED.generate_rsa_pair()
        path_public_key = os.path.join(fldr.UPLOAD_FOLDER, 'public_key.pub')
        path_private_key = os.path.join(fldr.UPLOAD_FOLDER, 'private_key.pem')
        f = open(path_private_key, "w+")
        f.write(private_key)
        f.close()
        f = open(path_public_key, "w+")
        f.write(public_key)
        f.close()

        return render_template('download2.html', header="Generated keys", path_public_key=path_public_key,
                               path_private_key=path_private_key)
    else:
        return render_template("generate.html")


@app.route("/nope")
def nope():
    return "I give up :("


#<input class="textarea form-control" type="textarea" id="text" name="text" rows="4">
@app.route("/chat/", methods=["POST", "GET"],defaults={'chatterID': 0})
@app.route("/chat/<int:chatterID>", methods=["POST", "GET"])
#@login_required
def chat(chatterID = 0):
    #print(chatterID)
    if request.method == "POST":
        
        message = request.form.get('message', "error")
        newUser = request.form.get('newUser', chatterID)
        if(message == "error" and newUser != chatterID):
            message = "Hello"
            newUser = User.getIdByUserName(newUser)
        #Moving forward code
        print(newUser)

        public_key_path = ("tmp/public_key.pub")

            

        text_file_string = message

        
        public_key_string = data_handler.read_public_key2(public_key_path)
        if not public_key_string:
            flash('Key has to have correct format !')
            return redirect(request.url)
        else:
            encrypted_text_string = ED.encrypt_file(text_file_string, public_key_string)
            unique_filename = str(uuid.uuid4())
            path = os.path.join(fldr.UPLOAD_FOLDER, unique_filename)
            f = open(path, "w+")
            f.write(encrypted_text_string)
            f.close()
            


        
        Message.create(1, newUser, path)
        json =getJSON(1)
        #print(selectMessages(1))
        return render_template("chat.html", messages=json, displayUser=chatterID)
    else:


        
        json =getJSON(1)
        #print(selectMessages(1))
        return render_template("chat.html", messages=json, displayUser=chatterID)

def getJSON(user_ID):
    struct = {}
    try:
        messages = selectMessages(user_ID)
        
        for message in messages:
            
            private_key_path = ("tmp/private_key.pem")
            private_key_string = data_handler.read_private_key2(private_key_path)
            fp = open(message.messageLocation, 'r')
            message_string = fp.read()
            fp.close() 
            decrypted_text_string = ED.decrypt_file(message_string , private_key_string)
            if (message.sender_ID==user_ID):
                #print(message.messageLocation)
                struct.setdefault(message.recipient_ID,[]).append(tuple((User.getUserNameById(message.sender_ID), decrypted_text_string)))
            if (message.recipient_ID==user_ID):
                #print(message.messageLocation)
                struct.setdefault(message.sender_ID,[]).append(tuple((User.getUserNameById(message.sender_ID), decrypted_text_string)))
            
        jsonData= json.dumps(struct)
        #print(jsonData)
        return struct
    except:
        return struct

def getUserName(id):
    return User.getUserNameById(id)



if __name__ == "__main__":
    app.jinja_env.globals.update(getUserName=getUserName)
    app.debug = True
    app.run(host='0.0.0.0')
    