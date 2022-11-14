import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from werkzeug.utils import secure_filename
import fldr

#TODO toto akosi nefunguje asi je ten subor obrovsky
def read_rockyou():
    text = []
    path = "/home/dbadmin/project/rockyou.txt"
    try:
        with open(path,'r') as file:
                for word in file:
                    text.append(word)
    except Exception:
        return []
    return text

def read_private_key(file, remove=False):
    filename = secure_filename(file.filename)
    path = os.path.join(fldr.UPLOAD_FOLDER, filename)
    file.save(path)
    if os.stat(path).st_size == 0:
        return False
    else:
        try:
            with open(path, "rb") as key_file:
                privateKey = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        except Exception:
            return False
        if remove:
            os.remove(path)
        return privateKey


def read_public_key(file, remove=False):
    filename = secure_filename(file.filename)
    path = os.path.join(fldr.UPLOAD_FOLDER, filename)
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
        if remove:
            os.remove(path)
        return publicKey

def read_public_key2(path):


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

def read_private_key2(path):


    if os.stat(path).st_size == 0:
        return False
    else:
        try:
            with open(path, "rb") as key_file:
                privateKey = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        except Exception:
            return False
        return privateKey

def read_public_key3(str):
    try:
        
        publicKey = serialization.load_pem_public_key(
            str.encode(),
            backend=default_backend()
        )
        
    except Exception:
        return False

    return publicKey

def read_private_key3(str):
    try:
        privateKey = serialization.load_pem_private_key(
            str.encode(),
            password=None,
            backend=default_backend()
        )
    except Exception:
        return False
    return privateKey


# ak je remove = True, tak file zmaže
def read_file(file, remove=False):
    filename = secure_filename(file.filename)
    path = os.path.join(fldr.UPLOAD_FOLDER, filename)
    file.save(path)
    if os.stat(path).st_size == 0:
        return False
    else:
        with open(path, 'r') as file:
            string = file.read()
        if remove:
            os.remove(path)
        return string