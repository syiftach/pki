from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os
from typing import List, Union
import pickle
import json

KEYS_PATH = os.path.abspath('keys')
JSON_PATH = os.path.abspath('json')


# ============================================ ASYMMETRIC_ENCRYPTION ============================================ #

def generate_keys_pair(pr_name, pb_name):
    pr_key_file = f'{KEYS_PATH}/{pr_name}.pem'
    pb_key_file = f'{KEYS_PATH}/{pb_name}.pem'

    # generate key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    # serialize keys
    pem_pr = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PrivateFormat.PKCS8,
                                       encryption_algorithm=serialization.NoEncryption())
    pem_pb = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PublicFormat.SubjectPublicKeyInfo)
    # write keys
    with open(pr_key_file, 'wb') as file:
        file.write(pem_pr)
    with open(pb_key_file, 'wb') as file:
        file.write(pem_pb)
    return private_key, public_key


def load_keys_pair(pr_name, pb_name):
    pr_key_file = f'{KEYS_PATH}/{pr_name}.pem'
    pb_key_file = f'{KEYS_PATH}/{pb_name}.pem'
    if os.path.exists(pr_key_file) and os.path.exists(pb_key_file):
        with open(pr_key_file, 'rb') as file:
            private_key = serialization.load_pem_private_key(file.read(), password=None, backend=default_backend())
        with open(pb_key_file, 'rb') as file:
            public_key = serialization.load_pem_public_key(file.read(), backend=default_backend())
        return private_key, public_key
    else:
        raise FileNotFoundError('could not find private key file or public key file')


def encrypt(key, message: bytes):
    assert isinstance(message, bytes)
    pad = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    cipher_text = key.encrypt(message, pad)
    return cipher_text


def decrypt(key, message):
    pad = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    plain_text = key.decrypt(message, pad)
    return plain_text


def sign(pr_key, message: bytes) -> bytes:
    signature = pr_key.sign(message,
                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA256())
    return signature


def verify(pb_key, message: bytes, signature: bytes) -> bool:
    try:
        pb_key.verify(signature,
                      message,
                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                      hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def get_key_bytes_format(key):
    if isinstance(key, rsa.RSAPrivateKey):
        return key.private_bytes(encoding=serialization.Encoding.DER,
                                 format=serialization.PrivateFormat.PKCS8,
                                 encryption_algorithm=serialization.NoEncryption())
    elif isinstance(key, rsa.RSAPublicKey):
        return key.public_bytes(encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo)
    else:
        raise TypeError('given key must be of type rsa')


# ============================================ SYMMETRIC_ENCRYPTION ============================================ #
def generate_key(key_name=None):
    if key_name is None:
        key_filename = f'{KEYS_PATH}/sym_key.key'
    else:
        key_filename = f'{KEYS_PATH}/{key_name}.key'
    if os.path.exists(key_filename):
        return load_key(key_filename)
    key = Fernet.generate_key()
    with open(key_filename, 'wb') as output_key:
        output_key.write(key)
    return key


def load_key(key_name):
    if not os.path.exists(f'{KEYS_PATH}/{key_name}.key'):
        raise FileNotFoundError
    with open(f'{KEYS_PATH}/{key_name}.key', 'rb') as key_file:
        return key_file.read()


def encrypt_symm(key, message: Union[str, bytes]):
    if isinstance(message, str):
        byte_msg = message.encode()
    else:
        byte_msg = message
    fernet_key = Fernet(key)
    cipher_txt = fernet_key.encrypt(byte_msg)
    return cipher_txt


def decrypt_symm(key, message):
    fernet_key = Fernet(key)
    plain_txt = fernet_key.decrypt(message)
    return plain_txt


# ============================================ FILE_FUNCTIONS ============================================ #


def generate_example_file():
    """
    generate an example client data file with 16348 lines, all with length of DATA_LEN
    @return:
    """
    line = 'defghijklmnopqrstuvwxyz012345678'
    with open('./example_file.txt', 'w') as file:
        for i in range(16348):
            file.write(f'{i}-{line[len(str(i)) + 1:]}\n')


def load_pickle(filename):
    with open(filename, 'rb') as pkl:
        return pickle.load(pkl)


def save_pickle(filename, data):
    with open(filename, 'wb') as pkl:
        pickle.dump(data, pkl)


def save_json(filename, data):
    json_str = json.dumps(data, indent=4)
    with open(f'{JSON_PATH}/{filename}', 'w') as file:
        file.write(json_str)


def load_json(filename):
    with open(f'{JSON_PATH}/{filename}', 'r') as file:
        return json.load(file)


def keys_loader(keys):
    assert isinstance(keys, tuple) or isinstance(keys, list)
    pr_name, pb_name = keys
    try:
        return load_keys_pair(pr_name, pb_name)
    except FileNotFoundError:
        return generate_keys_pair(pr_name, pb_name)


def key_loader(key):
    try:
        return load_key(key)
    except FileNotFoundError:
        return generate_key(key)
