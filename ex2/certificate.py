import enum
import datetime
from hashlib import sha256
import os

# project imports
from ex2.utils import get_key_bytes_format, verify

CRT_PATH = os.path.join('..', 'certificates')

DEFAULT_NOT_AFTER = datetime.datetime(year=2022, month=12, day=31, hour=23, minute=59)
DEFAULT_NOT_BEFORE = datetime.datetime(year=2022, month=1, day=1, hour=0, minute=0)


# todo: currently not being used
class KeyUsages(enum.Enum):
    ServerAuthentication = 0
    ClientAuthentication = 1
    CertificateSigning = 3
    DigitalSignature = 4
    CertificateIssuing = 5


FULL_PERMISSIONS = frozenset({KeyUsages.ServerAuthentication,
                              KeyUsages.ClientAuthentication,
                              KeyUsages.CertificateSigning,
                              KeyUsages.DigitalSignature,
                              KeyUsages.CertificateIssuing})


class Certificate:
    """
    this class represents an authentication certificate
    """

    def __init__(self, issuer, subject, key, validity, signature,
                 alt_names=frozenset(),
                 is_ca=False,
                 key_usages=frozenset()):
        assert isinstance(validity, tuple) or isinstance(validity, list), 'need to supply not-before and not-after'
        # name of root CA who issued the certificate
        self.issuer = issuer
        self.subject = subject  # name of subject this certificate was issued for
        # public key belongs to the subject
        self.pb_key = key
        # certificate is valid between this dates
        self.not_before = validity[0]
        self.not_after = validity[1]
        # signature signed by the issuer of the certificate
        self.signature = signature
        # alternate domain names who also inherit this certificate
        self.subject_alt_names = alt_names
        # CA constraint
        self.is_ca = is_ca
        # action that can be made with this certificate
        self.key_usages = key_usages
        # self.content_hash = content_hash

    def __str__(self):
        return f'{self.issuer.name}->{self.subject.name}'

    def __repr__(self):
        return 'CRT'

    def __eq__(self, other):
        return self.get_cid() == other.get_cid()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.get_cid())

    def get_public_key(self):
        return self.pb_key

    def get_signature(self):
        return self.signature

    def get_subject_alt_names(self):
        return self.subject_alt_names

    def is_valid(self):
        """
        @return: valid: bool, true if certificate is valid, false otherwise
        """
        today = datetime.datetime.today()
        return (self.not_before <= today < self.not_after) and \
               verify(self.issuer.get_public_key(), self.get_content_hash(), self.signature)

    def is_root_certificate(self):
        """
        @return: is_root: bool, true if certificate issuer is a root CA, false otherwise
        """
        return self.issuer == self.subject

    def get_content_hash(self):
        """
        @return: hash: bytes, hash of certificate content, which was signed over by issuer's private key
        """
        # hash content of certificate
        return self.compute_cert_hash(self.subject, self.is_ca, (self.not_before, self.not_after),
                                      self.subject_alt_names, self.key_usages)

    def get_cid(self):
        """
        @return: cid: bytes, certificate ID. this is a hash over all the certificate content
        """
        h = sha256()
        h.update(self.get_content_hash() + self.signature)
        return h.digest()

    def verbose_print(self):
        """
        print pretty print of the certificate to stdout
        @return:
        """
        print(f'certificate: {self}:\n'
              f'----------------------\n'
              f'certificate ID: {self.get_cid().hex()}\n'
              f'issuer: {self.issuer.name}\n'
              f'subject: {self.subject.name}\n'
              f'valid not before: {self.not_before}\n'
              f'valid not after: {self.not_after}\n'
              f'CA permissions: {self.is_ca}\n'
              f'subject alternate names: {self.subject_alt_names}\n'
              f'----------------------\n'
              )

    @staticmethod
    def compute_cert_hash(entity, is_ca, validity, alt_names, key_usages):
        """
        static method that compute the hash content of a certificate. this hash is signed over by the issuer's
        public key

        @param entity: Entity, entity to issue a certificate for
        @param validity: tuple(datetime,datetime), validity range of certificate
        @param is_ca: bool, CA permission
        @param alt_names: list[str], list of alternate domain names of entity
        @param key_usages: set[KeyUsage]: currently not used
        @return: hash: bytes, hash of certificate content
        """
        assert isinstance(validity, tuple) or isinstance(validity, list)
        # hash content of certificate
        h = sha256()
        h.update(bytes(is_ca))
        # not before
        h.update(bytes(validity[0].day) + bytes(validity[0].month) + bytes(validity[0].year) +
                 bytes(validity[0].hour) + bytes(validity[0].minute))
        # not after
        h.update(bytes(validity[1].day) + bytes(validity[1].month) + bytes(validity[1].year) +
                 bytes(validity[1].hour) + bytes(validity[1].minute))
        for alt in alt_names:
            h.update(alt.encode())
        for usage in key_usages:
            h.update(bytes(usage.value))
        h.update(entity.name.encode())
        bytes_format = get_key_bytes_format(entity.get_public_key())
        # print(bytes_format.hex())
        h.update(bytes_format)
        return h.digest()
