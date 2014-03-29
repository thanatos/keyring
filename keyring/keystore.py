import base64 as _base64
import functools as _functools
import gzip as _gzip
import io as _io
import json as _json
import os as _os
import subprocess as _subprocess
import tempfile as _tempfile

import gnupg as _gnupg


class Gpg(object):
    def __init__(self):
        self._temp_dir = _tempfile.mkdtemp()
        self.gpg = _gnupg.GPG(gnupghome=self._temp_dir)
        self.closed = False

    def close(self):
        if not self.closed:
            self.gpg = None
            _subprocess.call(['rm', '-rf', '--', self._temp_dir])
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_value, exc_type, traceback):
        self.close()
        return False


def _base64_encode(data):
    return _base64.b64encode(data).decode('ascii')

def _base64_decode(encoded_data):
    return _base64.b64decode(encoded_data.encode('ascii'))


class DataBlob(object):
    def __init__(self, mimetype, data):
        self.mimetype = mimetype
        self.data = data

    def __repr__(self):
        return '{}.{}({!r}, {!r})'.format(
            self.__class__.__module__, self.__class__.__name__,
            self.mimetype, self.data
        )

    def __eq__(self, other):
        return (self.mimetype == other.mimetype and self.data == other.data)

    def __ne__(self, other):
        return not (self == other)


class DecryptionError(Exception):
    pass


def _wrap_gpg(f):
    @_functools.wraps(f)
    def wrapper(*args, **kwargs):
        own_gpg_wrapper = None
        try:
            if 'gpg' not in kwargs or kwargs['gpg'] is None:
                own_gpg_wrapper = Gpg()
                kwargs['gpg'] = own_gpg_wrapper.gpg
            return f(*args, **kwargs)
        finally:
            if own_gpg_wrapper is not None:
                own_gpg_wrapper.close()
    return wrapper


@_wrap_gpg
def write_keystore(filename, passphrase, data, cipher=None, gpg=None):
    actual_data = {}

    for k, blob in data.items():
        actual_data[k] = {
            'type': blob.mimetype,
            'data': _base64_encode(blob.data),
        }

    raw_stream = _io.BytesIO()
    text_stream = None
    gzip_stream = _gzip.GzipFile(fileobj=raw_stream, mode='wb')
    try:
        text_stream = _io.TextIOWrapper(gzip_stream, encoding='utf-8')
        _json.dump(actual_data, text_stream)
    finally:
        if text_stream is not None:
            text_stream.close()
        gzip_stream.close()

    cipher = True if cipher is None else cipher
    encrypted_data = gpg.encrypt(
        raw_stream.getvalue(),
        None,
        passphrase=passphrase,
        symmetric=cipher,
        armor=False,
    )

    temp_filename = filename + '.writing'
    fd = _os.open(temp_filename, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
    try:
        try:
            fh = _os.fdopen(fd, 'wb')
        except:
            _os.close(fd)
            raise

        with fh:
            fh.write(encrypted_data.data)

        _os.rename(temp_filename, filename)
    except:
        _os.unlink(temp_filename)


@_wrap_gpg
def read_keystore(filename, passphrase, gpg=None):
    with open(filename, 'rb') as fh:
        decrypted_data = gpg.decrypt_file(fh, passphrase=passphrase)

    if not decrypted_data.ok:
        raise DecryptionError()

    data_stream = _io.BytesIO(decrypted_data.data)
    gzip_stream = _gzip.GzipFile(fileobj=data_stream, mode='rb')
    try:
        text_stream = _io.TextIOWrapper(gzip_stream, encoding='utf-8')
        json_data = _json.load(text_stream)
    finally:
        gzip_stream.close()

    actual_data = {}
    for k, v in json_data.items():
        mimetype = v['type']
        data = _base64_decode(v['data'])
        actual_data[k] = DataBlob(mimetype, data)
    return actual_data
