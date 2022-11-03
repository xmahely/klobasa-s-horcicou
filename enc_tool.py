from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa as RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
import base64
import os
import fire
import bcrypt


def base64Encoding(input):
    dataBase64 = base64.b64encode(input)
    dataBase64P = dataBase64.decode("UTF-8")
    return dataBase64P


def base64Decoding(input):
    return base64.decodebytes(input.encode("ascii"))


def open_file(name):
    with open(name, 'r') as f:
        text = f.read()
    return text


def create_file(name, content, opt=None):

    if opt is not None:
        name = name + "_" + opt
    with open(name, 'w') as f:
        f.write(content)
    return


def generate_random_key():
    return Fernet.generate_key()


def rsa():
    keygen = RSA.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    pem_private_key = keygen.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public_key = keygen.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )

    create_file("id_rsa_public.pub", pem_public_key.decode())
    create_file("id_rsa.pem", pem_private_key.decode())

    return


def AES_encrypt(input, key):
    aes = AES.new(key, AES.MODE_GCM)
    encrypted, auth = aes.encrypt_and_digest(input)
    return encrypted, auth, aes.nonce


def AES_decrypt(input, nonce, auth, key):
    aes = AES.new(key, AES.MODE_GCM, nonce)
    decrypted = aes.decrypt_and_verify(input, auth)
    return decrypted


def encrypt(name, pub):
    public_key = read_public_key(pub)
    file_text = open_file(name)

    symmetric_key = generate_random_key()
    fernet = Fernet(symmetric_key)

    symmetric_enc = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    output_header = symmetric_enc + str.encode("/!/") + fernet.encrypt(str.encode(file_text))

    # * AES-GCM  ...  integrity
    aes_key = os.urandom(32)
    encrypted, auth, nonce = AES_encrypt(output_header, aes_key)

    output = base64Encoding(aes_key) + "-----" + base64Encoding(auth) \
             + "-----" + base64Encoding(nonce) + "-----" + base64Encoding(encrypted)

    create_file(name, output, "enc")
    return


def decrypt(name, pem):
    private_key = read_private_key(pem)
    file_text = open_file(name)

    tmp = file_text.split("-----")
    aes_key = base64Decoding(tmp[0])
    auth = base64Decoding(tmp[1])
    nonce = base64Decoding(tmp[2])
    text = base64Decoding(tmp[3])

    del tmp

    result = AES_decrypt(text, nonce, auth, aes_key)

    split = result.split(str.encode("/!/"))

    symmetric_key = private_key.decrypt(
        split[0],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    fernet = Fernet(symmetric_key)
    create_file(name, fernet.decrypt(split[1]).decode(), "dec")

    return


def read_private_key(filename):
    with open(filename, "rb") as key_file:
        privateKey = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return privateKey


def read_public_key(filename):
    with open(filename, "rb") as key_file:
        publicKey = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return publicKey


def psswd_hash(input):
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(input.encode(),salt)
    return hash, salt


if __name__ == '__main__':
    fire.Fire({
        'encrypt': encrypt,
        'decrypt': decrypt,
        'rsa': rsa
    })
