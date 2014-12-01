#!/usr/bin/python

import argparse as _argparse
import struct as _struct
import sys as _sys


# This program is a Python 2/3 ployglot. The following are support functions:
if _sys.version_info.major == 2:
    def _print(s):
        eval('print s', None, {'s': s})

    _range = xrange
else:
    def _print(s):
        eval('print(s)', None, {'s': s})

    _range = range


ALPHABETS = {
    'letters': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'numbers': '0123456789',
    'symbols': '~!@#$%^&*-_:;,.?',
    'more_symbols': '`\'\"\\/{}[]()<>',
}


def random_integer(rand_fh, upper):
    """Generate a random integer in [0, ``upper``) uniformly.

    This function chooses an integer from the range [0, ``upper``] uniformly.
    It *might* loop for an indeterminate length of time, if it isn't able to
    generate a suitable integer.
    """

    # Because we read random numbers as uint32s, we can only support numbers
    # representable as uint32s.
    assert upper < 2 ** 32, 'upper argument is out of range.'

    # This is the number of random numbers that we can use. There will be a bit
    # of "slack" at the top of the range that the RNG gives us, we simply can't
    # use these without making the distribution non-uniform.
    usable_choices = 2 ** 32 // upper * upper

    while True:
        data = rand_fh.read(4)
        n = _struct.unpack('>I', data)[0]
        if not (n < usable_choices):
            continue
        actual_n = n % upper
        return actual_n


def select_letter(rand_fh, alphabet):
    """Chooses uniformly at random a letter from the given alphabet."""

    index = random_integer(rand_fh, len(alphabet))
    return alphabet[index]


def make_password(alphabet, length):
    _print('Generating password.')
    password = []
    try:
        with open('/dev/random', 'rb') as rand_fh:
            for n in _range(length):
                _sys.stderr.write('\r\x1b[KGenerating character {}/{}…'.format(n, length))
                _sys.stderr.flush()
                password.append(select_letter(rand_fh, alphabet))
    finally:
        _sys.stderr.write('\r\x1b[K')
        _sys.stderr.flush()

    return ''.join(password)


def make_wifi_aes_key():
    with open('/dev/random', 'rb') as rand_fh:
        raw_key = rand_fh.read(256 / 8)

    return ''.join('{0:02x}'.format(ord(b)) for b in raw_key)


def main(args):
    parser = _argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    wifi_parser = subparsers.add_parser('wifi-aes')

    password_parser = subparsers.add_parser('password')
    password_parser.add_argument('alphabet')
    password_parser.add_argument('length', type=int)

    pargs = parser.parse_args(args)

    if pargs.command == 'wifi-aes':
        _print(make_wifi_aes_key())
    elif pargs.command == 'password':
        symbol_sets = pargs.alphabet.split('+')
        alphabet = ''
        for symbol_set in set(symbol_sets):
            alphabet += ALPHABETS[symbol_set.lower()]
        _print('Using alphabet:\n{!r}'.format(alphabet))
        _print(make_password(alphabet, pargs.length))
    else:
        parser.print_usage(_sys.stderr)
        _sys.exit(1)


if __name__ == '__main__':
    main(_sys.argv[1:])
