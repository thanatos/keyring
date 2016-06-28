import io as _io
import json as _json
import zipfile as _zipfile

from . import base as _base


_ZIP_KEYRING_MAGIC = 'application/vnd.keyring.v2-zip.magic'.encode('ascii')


class NotAZippedKeyring(Exception):
    pass


class CorruptZippedKeyring(Exception):
    def __init__(self, message):
        self.message = message
        super(CorruptZippedKeyring, self).__init__(message)


def _read_contents_file(zfile):
    with zfile.open('META-INF/CONTENTS', 'r') as zcontents:
        with _io.TextIOWrapper(zcontents, encoding='utf-8') as zdeco:
            json_contents = _json.load(zdeco)
    for obj in json_contents:
        yield obj['zip_path'], obj['mimetype']


def open_as_zip_keyring(fileobj):
    zfile = None
    try:
        zfile = _zipfile.ZipFile(fileobj, 'r')
        try:
            with zfile.open('META-INF/MAGIC', 'r') as zmagic:
                magic = zmagic.read()
        except:
            raise NotAZippedKeyring('Unable to read META-INF/MAGIC.')
        if magic != _ZIP_KEYRING_MAGIC:
            raise NotAZippedKeyring(
                'META-INF/MAGIC did not have the correct value.'
            )
        return zfile
    except (_zipfile.BadZipFile,) as err:
        if zfile is not None:
            zfile.close()
        raise NotAZippedKeyring('Not a ZIP file.') from err
    except:
        if zfile is not None:
            zfile.close()
        raise


class IoPassThrough(object):
    def __init__(self, fileobj):
        self.fileobj = fileobj

    def __enter__(self):
        return self.fileobj

    def __exit__(self, exc_type, exc_value, traceback):
        _ = exc_type, exc_value, traceback
        return False


_ZIP_MAGIC = frozenset((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'))


class V2ZipStore(_base.Keystore, dict):
    @staticmethod
    def magic_detect(fileobj):
        magic = fileobj.read(4)
        if len(magic) != 4:
            return False
        return magic in _ZIP_MAGIC

    @staticmethod
    def read(fileobj):
        store = V2ZipStore()
        with open_as_zip_keyring(fileobj) as zfile:
            contents = _read_contents_file(zfile)
            for zip_path, mimetype in contents:
                with zfile.open(zip_path, 'r') as zdata:
                    data = zdata.read()
                store[zip_path] = _base.Item(mimetype, data)

        return store

    def write(self, fileobj):
        with _zipfile.ZipFile(
                fileobj, mode='w', compression=_zipfile.ZIP_DEFLATED) as zfile:
            zfile.writestr('META-INF/MAGIC', _ZIP_KEYRING_MAGIC)
            contents_json = []
            for name, item in self.items():
                contents_json.append({
                    'zip_path': name,
                    'mimetype': item.mimetype,
                })
                zfile.writestr(name, item.data)
            zfile.writestr(
                'META-INF/CONTENTS',
                _json.dumps(contents_json).encode('utf-8'),
            )

    @staticmethod
    def _decompress(fileobj):
        return IoPassThrough(fileobj)

    @staticmethod
    def _compress(fileobj):
        return IoPassThrough(fileobj)
