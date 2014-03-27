#!/usr/bin/env python3
# coding: utf-8

import argparse
import getpass
import os.path
import sys

import keystore
import term


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
    objects = load_keystore(args.filename)

    for name, obj in objects.items():
        sys.stdout.write(
            '• {t.BOLD}{}{t.RESET} ({})\n'.format(
                name, obj.mimetype, t=term
            )
        )


def ks_get(args):
    objects = load_keystore(args.filename)

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
    password = getpass.getpass()
    objects = load_keystore(args.filename, password)

    if args.key in objects:
        sys.stderr.write(
            'Key “{}” already exists in keystore.\n'.format(args.key))
        sys.exit(1)

    sys.stdout.write('Enter data to store:\n')
    sys.stdout.write('(Send EOF to terminate.)\n')
    data = sys.stdin.buffer.read()
    mimetype = args.mimetype
    objects[args.key] = keystore.DataBlob(mimetype, data)
    keystore.write_keystore(args.filename, password, objects)


def ks_create(args):
    if os.path.exists(args.filename):
        sys.stderr.write(
            'File “{}” already exists; please remove it if you want to'
            ' overwrite it with a new keystore.\n'.format(args.filename))
        sys.exit(1)

    password = getpass.getpass()

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
    create_parser.add_argument('filename')

    list_parser = subparsers.add_parser('list', help='list entries')
    list_parser.add_argument('filename')

    get_parser = subparsers.add_parser('get', help='get entry')
    get_parser.add_argument('filename')
    get_parser.add_argument('key')

    set_parser = subparsers.add_parser('set', help='set an entry to a value')
    set_parser.add_argument('filename')
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
