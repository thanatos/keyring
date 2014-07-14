#!/usr/bin/env python3
# coding: utf-8

import argparse
import getpass
import io
import json
import os.path
import platform
import subprocess
import sys

from . import keystore
from . import _term


def _check_keyring_path_mode(path, expected_mode, type_str):
    stat = os.stat(path)
    if stat.st_mode & 0o777 != expected_mode:
        sys.stderr.write(
            'WARNING: Permissions on {0} are too permisive. They are {1}'
            ' instead of {2}, recommend running:\n'
            '  chmod {2} \'{0}\'\n'
            'to better protect data in that {3}.\n'.format(
                path,
                oct(stat.st_mode & 0o777)[2:], oct(expected_mode)[2:],
                type_str
            )
        )


def _check_keyring_file_mode(keyring_file):
    _check_keyring_path_mode(keyring_file, 0o600, 'file')

def _check_keyring_dir_mode(keyring_dir):
    _check_keyring_path_mode(keyring_dir, 0o700, 'directory')


def _get_default_filename():
    return os.path.join(os.environ['HOME'], '.keyring', 'keyring')

def _get_filename(args):
    filename = args.filename
    if filename is None:
        filename = _get_default_filename()
        _check_keyring_dir_mode(os.path.dirname(filename))

    _check_keyring_file_mode(filename)

    return filename


def _prompt(what):
    sys.stdout.write('{}: '.format(
        what
    ))
    sys.stdout.flush()
    line = sys.stdin.readline()
    return line.strip()


def load_keystore(filename, password=None):
    if password is None:
        password = getpass.getpass()
    try:
        objects = keystore.read_keystore(filename, password)
    except keystore.DecryptionError:
        sys.stderr.write('Failed to decrypt keystore: wrong password?\n')
        sys.exit(1)
    return objects


def ks_list(args):
    filename = _get_filename(args)
    objects = load_keystore(filename)

    if not objects:
        sys.stdout.write('Nothing in the keyring.\n')

    for name, obj in objects.items():
        sys.stdout.write(
            '• {t.BOLD}{}{t.RESET} ({})\n'.format(
                name, obj.mimetype, t=_term
            )
        )


def _interactive_get(filename):
    objects = load_keystore(filename)

    key = _prompt("Key")

    if key not in objects:
        sys.stderr.write(
            'No such key “{}” in keystore.\n'.format(key)
        )
        sys.exit(1)
    else:
        return objects[key]


def ks_get(args):
    filename = _get_filename(args)
    obj = _interactive_get(filename)
    sys.stdout.buffer.write(obj.data)


def ks_set(args):
    filename = _get_filename(args)
    password = getpass.getpass()
    objects = load_keystore(filename, password)

    key = _prompt("Key")
    if key in objects:
        sys.stderr.write(
            'Key “{}” already exists in keystore.\n'.format(key))
        sys.exit(1)

    mimetype = _prompt("Mimetype")

    sys.stdout.write('Enter data to store:\n')
    sys.stdout.write('(Send EOF to terminate.)\n')
    data = sys.stdin.buffer.read()
    objects[key] = keystore.DataBlob(mimetype, data)
    keystore.write_keystore(filename, password, objects)


def ks_delete(args):
    filename = _get_filename(args)
    password = getpass.getpass()
    objects = load_keystore(filename, password)

    key = _prompt("Key")
    if key not in objects:
        sys.stderr.write(
            'Key “{}” does not exist in keystore.\n'.format(key)
        )
        sys.exit(1)

    del objects[key]
    keystore.write_keystore(filename, password, objects)


def ks_create(args):
    keyring_path = os.path.join(os.environ['HOME'], '.keyring')
    if args.filename is None:
        if not os.path.exists(keyring_path):
            os.mkdir(keyring_path, 0o700)
        else:
            _check_keyring_dir_mode(keyring_path)
        args.filename = os.path.join(keyring_path, 'keyring')

    if os.path.exists(args.filename):
        sys.stderr.write(
            'File “{}” already exists; refusing to overwrite it in case you'
            ' want it. Please move or remove it if you want to overwrite it'
            ' with a new keystore.\n'.format(args.filename))
        sys.exit(1)

    password = getpass.getpass()
    confirmed = getpass.getpass('Confirm password: ')

    if password != confirmed:
        sys.stderr.write('Passwords did not match.\n')
        sys.exit(1)

    keystore.write_keystore(args.filename, password, {})


def ks_copypw(args):
    filename = _get_filename(args)
    obj = _interactive_get(filename)
    if obj.mimetype != 'application/login+json':
        sys.stderr.write('Object doesn\'t appear to contain login details.\n')
        sys.exit(1)
    data = json.loads(obj.data.decode('utf-8'))
    if 1 < len(data):
        while True:
            sys.stdout.write(
                'Multiple logins under this name. Enter which one to copy:\n'
            )
            number_to_login = {}
            name_to_login = {}
            for n, login in enumerate(data, start=1):
                if 'username' not in login and 'email' not in login:
                    sys.stderr.write(
                        'Couldn\'t determine a name for login #{}.\n'.format(n)
                    )
                    continue
                else:
                    sys.stdout.write(
                        '{}. {}'.format(n, name)
                    )
                    if name in name_to_login:
                        name_to_login[name] = None
                    else:
                        name_to_login[name] = login
                    number_to_login[n] = login
            sys.stdout.write('Selection? [number or name] ')
            sys.stdout.flush()
            selection = sys.stdin.readline().strip()
            try:
                selection = int(selection)
            except ValueError:
                is_number = False
            if is_number:
                which = number_to_login[selection]
            else:
                which = name_to_login[selection]
    else:
        which = data[0]

    password_file_obj = io.BytesIO()
    password_file_obj.write(which['password'].encode('utf-8'))
    if platform.system() == 'Darwin':
        copy_program = ['pbcopy']
    else:
        copy_program = ['xsel', '-b']
    proc = subprocess.Popen(copy_program, stdin=subprocess.PIPE)
    proc.communicate(which['password'].encode('utf-8'))
    if proc.returncode != 0:
        sys.exit(1)
    print('Copied to the clipboard.')


def ks_changepw(args):
    filename = _get_filename(args)
    objects = load_keystore(filename)

    new_password = getpass.getpass('New password: ')
    confirm_password = getpass.getpass('Confirm password: ')

    if new_password != confirm_password:
        sys.stderr.write('Passwords did not match.\n')
        sys.exit(1)

    keystore.write_keystore(filename, new_password, objects)


def main(args):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    commands = {
        'create': ks_create,
        'list': ks_list,
        'get': ks_get,
        'set': ks_set,
        'delete': ks_delete,
        'copypw': ks_copypw,
        'change-password': ks_changepw,
    }

    def add_filename(parser):
        parser.add_argument(
            '-f', action='store', dest='filename',
            help='the filename of the keyring',
        )

    create_parser = subparsers.add_parser('create', help='create a new keystore')
    add_filename(create_parser)

    list_parser = subparsers.add_parser('list', help='list entries')
    add_filename(list_parser)

    get_parser = subparsers.add_parser('get', help='get entry')
    add_filename(get_parser)

    set_parser = subparsers.add_parser('set', help='set an entry to a value')
    add_filename(set_parser)

    delete_parser = subparsers.add_parser('delete', help='delete an entry')
    add_filename(delete_parser)

    copypw_parser = subparsers.add_parser('copypw', help='copy a password to the clipboard')
    add_filename(copypw_parser)

    change_password_parser = subparsers.add_parser(
        'change-password', help='change the password to the keyring'
    )
    add_filename(change_password_parser)

    pargs = parser.parse_args(args)
    if pargs.command is not None:
        commands[pargs.command](pargs)
    else:
        parser.print_usage(sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    import sys as _sys
    main(_sys.argv[1:])
