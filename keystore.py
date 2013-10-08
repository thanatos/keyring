import base64
import gzip
import io
import json
import subprocess
import tempfile

import gnupg


def get_gpg():
    dirname = tempfile.mkdtemp()

    gpg = gnupg.GPG(gnupghome=dirname)
    def clean_gpg():
        subprocess.call(['rm', '-rf', '--', dirname])

    return gpg, clean_gpg


def read_keystore(filename, gpg, passphrase):
    with open(filename, 'rb') as fh:
        data = gpg.decrypt_file(fh, passphrase=passphrase)

    data_stream = io.BytesIO(data.data)
    with gzip.GzipFile(fileobj=data_stream, mode='rb') as gzfile:
        json_data = gzfile.read().decode('utf-8')
    raw_data = json.loads(json_data)

    for k in raw_data:
        pre_decode_v = raw_data[k]
        # b64decode strangely uses bytes, not str…
        v = base64.b64decode(pre_decode_v.encode('ascii'))
        raw_data[k] = v
    return raw_data


def write_keystore(filename, gpg, passphrase, data, cipher=None):
    actual_data = {}
    for k, v in data.items():
        encoded_v = base64.b64encode(v)
        # b64encode strangely gives use bytes, not str…
        encoded_v = encoded_v.decode('ascii')
        actual_data[k] = encoded_v

    json_data = json.dumps(actual_data).encode('utf-8')

    data_stream = io.BytesIO()
    with gzip.GzipFile(fileobj=data_stream, mode='wb') as gzfile:
        gzfile.write(json_data)

    cipher = True if cipher is None else cipher
    encrypted_data = gpg.encrypt(
        data_stream.getvalue(),
        None,
        passphrase=passphrase,
        symmetric=cipher,
        armor=False,
    )

    fd = os.open(filename, os.O_WRONLY, 0o600)
    with open(filename, 'wb') as fh:
        fh.write(encrypted_data.data)
