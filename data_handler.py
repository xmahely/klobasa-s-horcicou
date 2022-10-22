import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'C:/Users/mmahe/OneDrive/Počítač/UPB/tmp'


def read_private_key(file):
    filename = secure_filename(file.filename)
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)
    if os.stat(path).st_size == 0:
        return False
    else:
        try:
            with open(filename, "rb") as key_file:
                privateKey = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        except Exception:
            return False
        return privateKey


def read_public_key(file):
    filename = secure_filename(file.filename)
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)
    if os.stat(path).st_size == 0:
        return False
    else:
        try:
            with open(path, "rb") as key_file:
                publicKey = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        except Exception:
            return False
        return publicKey


# ak je remove = True, tak file zmaže
def read_file(file, remove=False):
    filename = secure_filename(file.filename)
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)
    if os.stat(path).st_size == 0:
        return False
    else:
        with open(path, 'r') as file:
            string = file.read()
        if remove:
            os.remove(path)
        return string