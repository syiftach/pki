from typing import Dict, Set
from abc import ABC

from ex2.certificate import Certificate, DEFAULT_NOT_BEFORE, DEFAULT_NOT_AFTER, KeyUsages
from ex2.utils import *


class Entity(ABC):
    """
    this class represents a  entity in the network. this is a super class of the network servers
    entities. this could be a root CA, CA, Subject.
    this is a super class of CA, Subject
    """

    def __init__(self, name, domain, keys=('entity_pr_key', 'entity_pb_key')):
        # init keys
        pr_key, pb_key = keys_loader(keys)
        self._pr_key = pr_key
        self._pb_key = pb_key
        # name of entity
        self.name: str = name
        # domain of entity
        self.domain: str = domain
        # history of issued certificates: mapping from cid to certificate
        self._issued_certificates: Dict[bytes, Certificate] = dict()
        # mapping from subject name to its issued valid certificates
        self._valid_certificates: Dict[str, Set[Certificate]] = dict()
        # mapping from subject name to its invalid revoked certificates
        self._revoked_certificates: Dict[str, Set[Certificate]] = dict()
        # most recent certificated issued to entity
        self.certificate: [Certificate, None] = None

    def __eq__(self, other):
        return get_key_bytes_format(self._pb_key) == get_key_bytes_format(other.get_public_key())

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(get_key_bytes_format(self._pb_key))

    def get_public_key(self):
        return self._pb_key

    def get_subject_certificates(self):
        return self._valid_certificates

    def get_revocation_list(self):
        self.update()
        return self._revoked_certificates

    def get_certificate(self):
        return self.certificate

    def update(self):
        """
        update the dictionaries of this entity. discard all invalid certificates
        @return:
        """
        for entity_name, certs in self._valid_certificates.items():
            for crt in certs:
                if not crt.is_valid():
                    # remove from valid issued certificates
                    self._valid_certificates[entity_name].discard(crt)
                    # add to subject's revoked certificates
                    self._revoked_certificates[entity_name].add(crt)

    def issue(self, entity,
              validity=(DEFAULT_NOT_BEFORE, DEFAULT_NOT_AFTER), is_ca=False,
              alt_names=frozenset(), key_usages=frozenset()):
        """
        issue a certificate for given entity

        @param entity: Entity, entity to issue a certificate for
        @param validity: tuple(datetime,datetime), validity range of certificate
        @param is_ca: bool, CA permission
        @param alt_names: list[str], list of alternate domain names of entity
        @param key_usages: set[KeyUsage]: currently not used
        @return: certificate: Certificate, issued certificate
        """
        if self.get_certificate() is None or not self.get_certificate().is_ca:
            raise ValueError('only entities with CA permission can issue a certificate')
        # compute certificate content hash
        content_hash = Certificate.compute_cert_hash(entity, is_ca, validity, alt_names, key_usages)
        # sign over the hash
        signature = sign(self._pr_key, content_hash)
        # create certificate
        crt = Certificate(self, entity, entity.get_public_key(), validity, signature, alt_names, is_ca, key_usages)
        entity.receive_certificate(crt)
        # add new certificate to dictionary
        if self._valid_certificates.get(crt.subject.name) is None:
            self._valid_certificates[crt.subject.name] = {crt}
            self._revoked_certificates[crt.subject.name] = set()
        else:
            self._valid_certificates[crt.subject.name].add(crt)
        self._issued_certificates[crt.get_cid()] = crt
        return crt

    def revoke(self, subject, certificate):
        """
        revoke given certificate from given subject
        @param subject: Subject, subject to revoke the certificate from
        @param certificate: Certificate, certificate to revoke
        @return:
        """
        certs = self._valid_certificates.get(subject.name, None)
        # can only revoke a certificate that corresponds to the given subject
        if certificate.subject != subject:
            raise ValueError('given certificates does not correspond to given subject')
        # only certificate issuer can revoke a certificate he issued
        elif certificate.issuer != self:
            raise ValueError(f'only the certificate issuer ({certificate.issuer.name}) can revoke this certificate')
        # check if there exists a certificate to revoke
        elif certs is None or certs == set():
            raise ValueError(f'no valid certificate to revoke for given subject')
        # revoke subject's certificate
        self._valid_certificates[subject.name].discard(certificate)
        self._revoked_certificates[subject.name].add(certificate)
