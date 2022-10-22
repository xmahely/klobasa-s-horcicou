import os
from flask import Flask, redirect, url_for, render_template, request, flash, send_file
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

import test
import data_handler
import encrypt_decrypt

UPLOAD_FOLDER = 'C:/Users/mmahe/OneDrive/Počítač/UPB/tmp'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024
app.secret_key = 'super secret key'


@app.route("/")
def home():
    return render_template("index.html")


def allowed_file(file, extension):
    if len(file.split('.')) > 2:
        return False
    return '.' in file and file.rsplit('.', 1)[1].lower() == extension


@app.route("/download/<path>")
def download_file(path):
    return send_file(path, as_attachment=True)


@app.route("/encrypt", methods=["POST", "GET"])
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
        public_key_string = data_handler.read_public_key(public_key)
        if not public_key_string:
            flash('Key has to have correct format !')
            return redirect(request.url)
        else:
            decrypted_text_string = encrypt_decrypt.encrypt_file(text_file_string, public_key_string)
            f = open('encrypted.txt', "w+")
            f.write(decrypted_text_string)
            f.close()
            # path = os.path.join(UPLOAD_FOLDER, 'encrypted')
            # skuste sa pohrat s tymito cestami, aby to napr. islo z priecinku tmp
            path = "encrypted.txt"
            return render_template('download.html', header="Encrypted file", path_download=path)
    else:
        return render_template("encrypt.html")


@app.route("/decrypt", methods=["POST", "GET"])
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
        private_key_string = data_handler.read_private_key(private_key)
        if not private_key_string:
            flash('Key has to have correct format !')
            return redirect(request.url)
        else:
            decrypted_text_string = encrypt_decrypt.decrypt_file(text_file_string, private_key_string)
            f = open('decrypted.txt', "w+")
            f.write(decrypted_text_string)
            f.close()
            # path = os.path.join(UPLOAD_FOLDER, 'encrypted')
            # skuste sa pohrat s tymito cestami, aby to napr. islo z priecinku tmp
            path = "decrypted.txt"
            return render_template('download.html', header="Decrypted file", path_download=path)
    else:
        return render_template("decrypt.html")


@app.route("/generate", methods=["POST", "GET"])
def generate_keys():
    if request.method == "POST":
        private_key, public_key = encrypt_decrypt.generate_rsa_pair()

        # skuste sa pohrat s tymito cestami, aby to napr. islo z priecinku tmp
        path_public_key = 'public_key.pub'
        path_private_key = 'private_key.pem'

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


if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0')
