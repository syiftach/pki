from typing import Dict

from ex2.utils import *
from ex2.entity import Entity
from ex2.certificate import Certificate

SUBJECT_NAMES = ['wikipedia', 'moodle', 'youtube', 'morfix']


class Subject(Entity):

    def __init__(self, name, domain, alt_names=frozenset(), keys=('subject_pr_key', 'subject_pb_key'),
                 sym_key='subject_key', data=None):
        # call super class: init keys, name, domain, and certificate data structures handling
        super().__init__(name, domain, keys)
        self._key = key_loader(sym_key)

        self.alt_names = alt_names
        # set of certificates issued to this subject
        self.certificates = set()
        self.data = data
        # mapping from client address (public key bytes) to symmetric key
        self._client_key: Dict[bytes, bytes] = dict()

    def __str__(self):
        return f'{self.name}-(Subject)'

    def __repr__(self):
        return 'Subject'

    def set_certificate(self, certificate: Certificate):
        """
        set certificate field for subject
        @param certificate: Certificate
        @return:
        """
        self.certificates = certificate

    def receive_certificate(self, certificate):
        """
        add certificate to issued certificates. if main certificate is None set it to given certificate
        @param certificate: Certificate
        @return:
        """
        self.certificate = certificate
        self.certificates.add(certificate)

    def exchange_key(self, address, client_key):
        """
        exchange symmetric key with caller client
        @param address: bytes, bytes of public key of caller client
        @param client_key: bytes, symmetric key to exchange
        @return:
        """
        self._client_key[address] = decrypt(self._pr_key, client_key)

    def get_data(self, address):
        """
        return server data to caller. data is encrypted with symmetric key corresponding to given address
        @param address: bytes, bytes of public key of client
        @return: enc_data: bytes, encrypted data
        """
        key = self._client_key.get(address, None)
        if key is None:
            raise ValueError('(Server) failed to send data: could not authenticate client')
        # send encrypted data and the signature over plain data, for the client to verify
        return encrypt_symm(key, str(self.data)), sign(self._pr_key, str(self.data).encode())


# ============================= HELPER_FUNCTIONS ============================= #

def generate_json_file_examples():
    assert os.path.exists(JSON_PATH)
    prefixes = ['media', 'books', 'movies', 'jobs', 'games', 'kids', 'mobile']
    for name in SUBJECT_NAMES:
        domain = f'*.{name}.com'
        alt_names = [domain]
        data = []
        for prefix in prefixes:
            alt_names.append(f'*.{prefix}.{name}.com')
            data.append(f'{name}-{prefix}-data')
        d = {'name': name, 'domain': domain, 'alt_names': alt_names, 'data': data}
        save_json(f'{name}.json', d)


def load_subjects_from_json():
    subjects = []
    for name in SUBJECT_NAMES:
        data = load_json(f'{name}.json')
        subject = Subject(name, data['domain'], alt_names=data['alt_names'],
                          keys=(f'{name}_pr_key', f'{name}_pb_key'),
                          data=data['data'])
        subjects.append(subject)
    return subjects
