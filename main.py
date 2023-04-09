from collections import namedtuple
import os
from typing import Dict

from ex2 import *

ENTITIES = ['wikipedia', 'moodle', 'youtube', 'morfix', 'google']

MAIN_MENU_MSG = "\nmain menu: enter index of selection\n" \
                "---------------\n" \
                "1. issue certificate\n" \
                "2. revoke certificate\n" \
                "3. connect to server\n" \
                "4. list valid certificates\n" \
                "5. list revoked certificates\n" \
                "6. update client\n" \
                "7. exit"

ENTITIES_LIST_MSG = "google\n" \
                    "wikipedia\n" \
                    "moodle\n" \
                    "youtube\n" \
                    "morfix\n" \
                    "enter \'5\' to go back"

SUBJECT_LIST_MSG = "1. wikipedia\n" \
                   "2. moodle\n" \
                   "3. youtube\n" \
                   "4. morfix\n" \
                   "5. go back to main menu"

INVALID_INPUT_MSG = 'ERROR: given input is invalid'
ISSUE_FORMAT_MSG = "write selection in the following format: <issuer>,<subject>,[ca]"
REVOKE_FORMAT_MSG = "write selection in the following format: <issuer>,<subject>"

ISSUE_MENU_MSG = f"\nissue certificate menu:\n{ISSUE_FORMAT_MSG}\n" \
                 f"----------------------\n" \
                 f"{ENTITIES_LIST_MSG}"

REVOKE_MENU_MSG = f"\nrevoke certificate menu:\n{REVOKE_FORMAT_MSG}\n" \
                  f"----------------------\n" \
                  f"{ENTITIES_LIST_MSG}"

CONNECT_MENU_MSG = f"\nconnect menu:\n" \
                   f"to select server to connect to, enter the correct index\n" \
                   f"----------------------\n" \
                   f"{SUBJECT_LIST_MSG}"

Request = namedtuple('Request', ['issuer', 'subject', 'ca'])

CANCEL = '5'


class MainMenuOption:
    ISSUE = '1'
    REVOKE = '2'
    CONNECT = '3'
    LIST_VALID = '4'
    LIST_REVOKED = '5'
    UPDATE = '6'
    EXIT = '7'


class SubjectOption:
    WIKIPEDIA = '1'
    MOODLE = '2'
    YOUTUBE = '3'
    MORFIX = '4'
    CANCEL = '5'


def load_subjects():
    """
    load subjects from json files
    @return: Dict[str,Subject]
    """
    loaded_subjects = load_subjects_from_json()
    d = dict()
    for subject in loaded_subjects:
        d[subject.name] = subject
    return d


def parse_input(user_input, entities):
    """
    simple parser to parse the user input
    @param user_input: str, user input
    @param entities: dict[str,Entity], dictionary of entities
    @return: request: Request (namedtuple)
    """
    if user_input == CANCEL:
        return user_input
    result = user_input.split(',')
    if len(result) < 2 or result[0] not in ENTITIES or result[1] not in ENTITIES or len(result) > 3:
        print(INVALID_INPUT_MSG)
        return None
    elif result[0] == result[1]:
        print('selected entities have to be different')
        return None
    elif result[1] == 'google':
        print('selected subject is a root CA')
        return None
    elif len(result) == 2:
        return Request(entities[result[0]], entities[result[1]], False)
    elif len(result) == 3 and result[2] == 'ca':
        return Request(entities[result[0]], entities[result[1]], True)


def issue_submenu(entities: Dict[str, Entity]):
    """
    issue sub-menu loop
    @param entities:
    @return:
    """
    print(ISSUE_MENU_MSG)
    while True:
        user_input = input('(issue) option: ')
        result = parse_input(user_input, entities)
        if user_input == CANCEL:
            print(MAIN_MENU_MSG)
            return
        if result is None:
            continue
        issuer, subject = result.issuer, result.subject
        try:
            issuer.issue(subject, is_ca=result.ca, alt_names=subject.alt_names)
        except ValueError as e:
            print(e)


def revoke_submenu(entities: Dict[str, Entity]):
    """
    revoke submenu loop
    @param entities:
    @return:
    """
    print(REVOKE_MENU_MSG)

    while True:
        user_input = input('(revoke) option: ')
        result = parse_input(user_input, entities)
        if user_input == CANCEL:
            print(MAIN_MENU_MSG)
            return
        if result is None:
            continue
        issuer, subject = result.issuer, result.subject
        if subject.get_certificate() is None:
            print('ERROR: no certificate to revoke')
        try:
            for cert in subject.certificates:
                # if cert.issuer == issuer:
                issuer.revoke(subject, cert)
        except ValueError as e:
            print(e)
            print('ERROR: failed to revoke')
            continue


def connect_submenu(client: Client, subjects: Dict[str, Subject]):
    """
    connect to server sub menu loop
    @param client: Client
    @param subjects: Dict[str,Subject]
    @return:
    """
    print(CONNECT_MENU_MSG)
    while True:
        user_input = input('(connect) option: ')
        try:
            if user_input == SubjectOption.WIKIPEDIA:
                wiki = subjects['wikipedia']
                client.connect(wiki)
            elif user_input == SubjectOption.MOODLE:
                moodle = subjects['moodle']
                client.connect(moodle)
            elif user_input == SubjectOption.YOUTUBE:
                youtube = subjects['youtube']
                client.connect(youtube)
            elif user_input == SubjectOption.MORFIX:
                morfix = subjects['morfix']
                client.connect(morfix)
            elif user_input == SubjectOption.CANCEL:
                print(MAIN_MENU_MSG)
                return
            else:
                print(INVALID_INPUT_MSG)
        except ValueError as e:
            print(e)


def main(entity_dict: Dict[str, Entity], subject_dict: Dict[str, Subject], client: Client):
    """
    main menu loop
    @param entity_dict: dictionary of all entities, including CA, Subject
    @param subject_dict: dictionary of Subject, server a client can connect to
    @param client: Client, client instance
    @return:
    """
    print(MAIN_MENU_MSG)
    while True:
        user_input = input('(main) option: ')
        if user_input == MainMenuOption.ISSUE:
            issue_submenu(entity_dict)
        elif user_input == MainMenuOption.REVOKE:
            revoke_submenu(entity_dict)
        elif user_input == MainMenuOption.CONNECT:
            connect_submenu(client, subject_dict)
        elif user_input == MainMenuOption.LIST_VALID:
            for ca_name, ca in entity_dict.items():
                certs_map = ca.get_subject_certificates()
                for name, certs in certs_map.items():
                    if certs != set():
                        print(f'valid certificates issued for {name}')
                    for cert in certs:
                        cert.verbose_print()
        elif user_input == MainMenuOption.LIST_REVOKED:
            for ca_name, ca in entity_dict.items():
                revoked_certs_map = ca.get_revocation_list()
                for name, certs in revoked_certs_map.items():
                    if certs != set():
                        print(f'revoked certificates of {name}')
                    for cert in certs:
                        cert.verbose_print()
        elif user_input == MainMenuOption.UPDATE:
            for ca_name, ca in entity_dict.items():
                client.update(ca)
            print('client updated')
        elif user_input == MainMenuOption.EXIT:
            exit(0)
        else:
            print(INVALID_INPUT_MSG)


if __name__ == '__main__':
    if not os.path.exists('./ex2'):
        raise Exception('program should run from root folder!')
    if not os.path.exists('./json'):
        os.mkdir('json')
        generate_json_file_examples()
    if not os.path.exists('./keys'):
        os.mkdir('keys')
    google = CA('Google', '*.google.com', keys=('google_ca_pr', 'google_ca_pb'))
    entities_dict = load_subjects()
    subject_dict = entities_dict.copy()
    entities_dict.update({'google': google})
    client = Client()
    client.add_entity(google)
    print('PKI system (simple usage example)')
    main(entities_dict, subject_dict, client)
