# python imports
from __future__ import annotations
import datetime

# ex2 library imports
from ex2.utils import sign
from ex2.entity import Entity
from ex2.certificate import Certificate, FULL_PERMISSIONS

NOT_BEFORE_CA_DEFAULT = datetime.datetime(year=2000, month=1, day=1)
NOT_AFTER_CA_DEFAULT = datetime.datetime(year=2050, month=1, day=1)

CA_NAMES = ['google', 'LetsEncrypt', 'GOV']


class CA(Entity):
    """
    this class represents a root Certificate Authority (CA)
    """

    def __init__(self, name, domain, keys=('ca_pr_key', 'ca_pb_key')):
        # call super class: init keys, name, domain, and certificate data structures handling
        super().__init__(name, domain, keys)
        not_before = NOT_BEFORE_CA_DEFAULT
        not_after = NOT_AFTER_CA_DEFAULT
        # generate certificate
        hashed_content = Certificate.compute_cert_hash(self, True, (not_before, not_after), self.domain,
                                                       FULL_PERMISSIONS)
        signature = sign(self._pr_key, hashed_content)
        # issue certificate to self (root CA): the certificates is self-signed
        self.certificate = Certificate(self, self, self._pb_key, (not_before, not_after), signature,
                                       self.domain, True, FULL_PERMISSIONS)

    def __str__(self):
        return f'{self.name}-(CA)'

    def __repr__(self):
        return 'CA'
