#!/usr/bin/env python3
# coding: utf-8

import argparse
import getpass
import os.path
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


def ks_get(args):
    filename = _get_filename(args)
    objects = load_keystore(filename)

    if args.key not in objects:
        sys.stderr.write(
            'No such key “{}” in keystore.\n'.format(
                args.key
            )
        )
        sys.exit(1)
    else:
        sys.stdout.buffer.write(objects[args.key].data)


def ks_set(args):
    filename = _get_filename(args)
    password = getpass.getpass()
    objects = load_keystore(filename, password)

    if args.key in objects:
        sys.stderr.write(
            'Key “{}” already exists in keystore.\n'.format(args.key))
        sys.exit(1)

    sys.stdout.write('Enter data to store:\n')
    sys.stdout.write('(Send EOF to terminate.)\n')
    data = sys.stdin.buffer.read()
    mimetype = args.mimetype
    objects[args.key] = keystore.DataBlob(mimetype, data)
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


def main(args):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    ks_parser = subparsers.add_parser('keystore')

    commands = {
        'create': ks_create,
        'list': ks_list,
        'get': ks_get,
        'set': ks_set,
    }

    create_parser = subparsers.add_parser('create', help='create a new keystore')
    create_parser.add_argument('-f', action='store', dest='filename')

    list_parser = subparsers.add_parser('list', help='list entries')
    list_parser.add_argument('-f', action='store', dest='filename')

    get_parser = subparsers.add_parser('get', help='get entry')
    get_parser.add_argument('-f', action='store', dest='filename')
    get_parser.add_argument('key')

    set_parser = subparsers.add_parser('set', help='set an entry to a value')
    set_parser.add_argument('-f', action='store', dest='filename')
    set_parser.add_argument('key')
    set_parser.add_argument('mimetype')

    pargs = parser.parse_args(args)
    if pargs.command is not None:
        commands[pargs.command](pargs)
    else:
        parser.print_usage(sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    import sys as _sys
    main(_sys.argv[1:])
