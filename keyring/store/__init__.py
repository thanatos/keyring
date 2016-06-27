import functools as _functools
import io as _io
import os as _os
import subprocess as _sp
import tempfile as _tempfile

import gnupg as _gnupg

from . import v1_json


class Gpg(object):
    def __init__(self):
        self._temp_dir = _tempfile.mkdtemp()
        self.gpg = _gnupg.GPG(gnupghome=self._temp_dir)
        self.closed = False

    def close(self):
        if not self.closed:
            self.gpg = None
            _sp.call(['rm', '-rf', '--', self._temp_dir])
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_value, exc_type, traceback):
        self.close()
        return False


def _wrap_gpg(f):
    @_functools.wraps(f)
    def wrapper(*args, **kwargs):
        own_gpg_wrapper = None
        try:
            if 'gpg_context' not in kwargs or kwargs['gpg_context'] is None:
                own_gpg_wrapper = Gpg()
                kwargs['gpg_context'] = own_gpg_wrapper.gpg
            return f(*args, **kwargs)
        finally:
            if own_gpg_wrapper is not None:
                own_gpg_wrapper.close()
    return wrapper


class DecryptionError(Exception):
    pass


@_wrap_gpg
def read_keystore(filename, passphrase, gpg_context=None):
    with open(filename, 'rb') as fh:
        decrypted_data = gpg_context.decrypt_file(fh, passphrase=passphrase)

    if not decrypted_data.ok:
        raise DecryptionError()

    with _io.BytesIO(decrypted_data.data) as data_as_bytes_io, \
            _io.BufferedReader(data_as_bytes_io) as decrypted_fileobj:

        return v1_json.V1JsonStore.read(decrypted_fileobj)


@_wrap_gpg
def write_keystore(filename, passphrase, store, cipher=None, gpg_context=None):
    with _io.BytesIO() as data_fileobj:
        store.write(data_fileobj)

        cipher = True if cipher is None else cipher
        encrypted_data = gpg_context.encrypt(
            data_fileobj.getvalue(),
            None,
            passphrase=passphrase,
            symmetric=cipher,
            armor=False,
        )

    temp_filename = filename + '.writing'
    fd = _os.open(
        temp_filename,
        _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC,
        0o600,
    )
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
