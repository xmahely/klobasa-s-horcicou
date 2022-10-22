import os
from flask import Flask, redirect, url_for, render_template, request, flash, send_file
from werkzeug.utils import secure_filename
import test

UPLOAD_FOLDER = 'C:/Users/mmahe/OneDrive/Počítač/UPB/tmp'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'super secret key'


@app.route("/")
def home():
    return render_template("index.html")


def allowed_file(filename, extension):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == extension


def read_file(file):
    filename = secure_filename(file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)
    with open(path, 'r') as file:
        string = file.read()
    os.remove(path)
    return string


@app.route("/download/<path>")
def download_file(path):
    return send_file(path, as_attachment=True)


@app.route("/encrypt", methods=["POST", "GET"])
def encrypt():
    if request.method == "POST":
        if 'text_file' not in request.files or 'public_key' not in request.files:
            flash('Corrupted text file or public key')
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

        text_file_string = read_file(text_file)
        public_key_string = read_file(public_key)
        path = test.function(public_key_string, text_file_string)
        return render_template('download.html', header="Encrypted file", path_download=path)
    else:
        return render_template("encrypt.html")


@app.route("/decrypt", methods=["POST", "GET"])
def decrypt():
    if request.method == "POST":
        if 'text_file' not in request.files or 'private_key' not in request.files:
            flash('Corrupted text file or private key')
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

        text_file_string = read_file(text_file)
        private_key_string = read_file(private_key)
        path = test.function(private_key_string, text_file_string)
        return render_template('download.html', header="Decrypred file", path_download=path)
    else:
        return render_template("decrypt.html")

@app.route("/generate")
def generate_keys():
    return render_template("generate.html")


if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0')
