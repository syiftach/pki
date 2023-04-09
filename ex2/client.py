# python imports
from typing import Dict

# project imports
from ex2.utils import *
from ex2.entity import Entity
from ex2.certificate import Certificate
from ex2.subject import Subject

CLIENT = '(client)'
ERR_VERIFY_MSG = f'{CLIENT} failed to connect: could not verify certificate'
ERR_CONNECT_MSG = f'{CLIENT} failed to connect: untrusted server'
CONNECT_SUCCESS_MSG = f'{CLIENT} connected'


class Client:

    def __init__(self, keys=('client_pr_key', 'client_pb_key'), sym_key='client_key'):
        # init keys
        pr_key, pb_key = keys_loader(keys)
        self._pr_key = pr_key
        self._pb_key = pb_key
        self._key = key_loader(sym_key)

        # bytes representation of public key
        self.address = get_key_bytes_format(self._pb_key)
        # known entities
        self.known_entities: Dict[str, Entity] = dict()
        # all revoked certificates client heard about
        self.revoked_certificates = set()
        # entities the client exchanged symmetric key with
        self._subject_key: Dict[str, bytes] = dict()
        # todo: not used
        # all certificates saved on the client's side
        # self.known_certificates = set()

    def __str__(self):
        return f'Client-{self.address.hex()[:4]}'

    def __repr__(self):
        return 'Client'

    def get_public_key(self):
        return self._pb_key

    def add_entity(self, entity: Entity):
        """
        add entity to client known entities
        @param entity: Entity, entity to add
        @return:
        """
        self.known_entities[entity.name] = entity

    def remove_entity(self, entity: Entity):
        """
        remove entity from known-to-client entities
        @param entity: Entity, entity to remove
        @return:
        """
        self.known_entities.pop(entity.name, None)

    def update(self, entity: Entity):
        """
        update client's certificates local data
        @param entity: Entity, entity to get the receive the update from
        @return:
        """
        # get revoked certificates and update client
        revoked_certs = entity.get_revocation_list()
        for name, certs in revoked_certs.items():
            # remove known entity
            self.known_entities.pop(name, None)
            # update revoked certificates
            self.revoked_certificates.update(certs)

    def connect(self, server: Subject):
        """
        connect to the given server, using simple implementation of TLS protocol
        @param server: Subject, server to connect to and get data from
        @return:
        """
        cert = server.get_certificate()
        if not isinstance(cert, Certificate):
            raise ValueError(f'{CLIENT} server does not have certificate')
        # check if client trusts the CA or if server is known to client
        if cert.issuer.name in self.known_entities.keys() or cert.subject.name in self.known_entities.keys():
            # verify certificate validity
            if not cert.is_valid() or cert in self.revoked_certificates:
                raise ValueError(ERR_VERIFY_MSG)
            if self.known_entities.get(server.name, None) is None:
                self.add_entity(server)
                self.exchange_key(server)
            print(CONNECT_SUCCESS_MSG)
            # request data from server and verify it
            return self._data_request(server)
        else:
            current_cert = cert
            # go up the certificate chain until reaching a root CA
            while not current_cert.is_root_certificate():
                # get certificate of parent entity
                current_cert = current_cert.issuer.get_certificate()
                # reject if :
                # 1. issuer's certificate is not valid
                # 2. issuer does not have CA permissions
                # 3. given certificate was revoked by the issuer
                if not current_cert.is_valid() or not current_cert.is_ca or current_cert in self.revoked_certificates:
                    raise ValueError(ERR_VERIFY_MSG)
                elif current_cert.issuer.name in self.known_entities.keys():
                    # add subject to known subject
                    print(CONNECT_SUCCESS_MSG)
                    self.add_entity(server)
                    self.exchange_key(server)
                    # request data from server and verify it
                    return self._data_request(server)
            # if reached root CA, but it is not known to the user
            raise ValueError(ERR_CONNECT_MSG)

    def exchange_key(self, server: Subject):
        """
        exchange symmetric key with given server. the key is to be used after later connections,
        as long as this server is honest, legal and known to client.
        this exchange follows the simple TLS protocol

        @param server: Subject, server to exchange key with
        @return:
        """
        # client encrypts the symmetric key with server's public key
        server.exchange_key(self.address, encrypt(server.get_public_key(), self._key))

    def _data_request(self, server: Subject):
        """
        helper request data from server method.
        verifies the data received from server

        @param server: Subject, server which data was received from
        @return: data, str: plain data, if know exception was raised
        """
        enc_data, sig = server.get_data(self.address)
        plain_data = decrypt_symm(self._key, enc_data)
        if not verify(server.get_public_key(), plain_data, sig):
            raise InvalidSignature(f'{CLIENT} failed to get data: verification failed')
        " do something with data..."
        print(f'{CLIENT} received: f{plain_data}')
        return plain_data
