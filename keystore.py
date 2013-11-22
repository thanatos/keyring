import base64 as _base64
import gzip
import io
import json
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


def write_keystore(filename, gpg, passphrase, data, cipher=None):
    actual_data = {}

    for k, blob in data.items():
        actual_data[k] = {
            'type': blob.mimetype,
            'data': _base64_encode(blob.data),
        }

    raw_stream = io.BytesIO()
    gzip_stream = gzip.GzipFile(fileobj=raw_stream, mode='wb')
    text_stream = io.TextIOWrapper(gzip_stream, encoding='utf-8')
    json.dump(actual_data, text_stream)
    text_stream.close()  # will close gzip_stream too.

    print('raw_stream = {!r}'.format(raw_stream.closed))
    print('About to write:\n{!r}'.format(raw_stream.getvalue()))

    cipher = True if cipher is None else cipher
    encrypted_data = gpg.encrypt(
        raw_stream.getvalue(),
        None,
        passphrase=passphrase,
        symmetric=cipher,
        armor=False,
    )

    fd = _os.open(filename, _os.O_WRONLY, 0o600)
    with open(filename, 'wb') as fh:
        fh.write(encrypted_data.data)


def read_keystore(filename, gpg, passphrase):
    with open(filename, 'rb') as fh:
        decrypted_data = gpg.decrypt_file(fh, passphrase=passphrase)

    data_stream = io.BytesIO(decrypted_data.data)
    gzip_stream = gzip.GzipFile(fileobj=data_stream, mode='rb')
    text_stream = io.TextIOWrapper(gzip_stream, encoding='utf-8')
    json_data = json.load(text_stream)

    actual_data = {}
    for k, v in json_data.items():
        mimetype = v['type']
        data = _base64_decode(v['data'])
        actual_data[k] = DataBlob(mimetype, data)
    return actual_data
