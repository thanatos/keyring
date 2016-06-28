import base64 as _base64
import io as _io
import json as _json

from . import base as _base


def _base64_encode(data):
    return _base64.b64encode(data).decode('ascii')


def _base64_decode(encoded_data):
    return _base64.b64decode(encoded_data.encode('ascii'))


class V1JsonStore(_base.Keystore, dict):
    format = 'v1-json'

    @classmethod
    def _read_store_data(cls, fileobj):
        with _io.TextIOWrapper(fileobj, encoding='utf-8') as text_stream:
            json_data = _json.load(text_stream)

        store = cls()
        for k, v in json_data.items():
            mimetype = v['type']
            data = _base64_decode(v['data'])
            store[k] = _base.Item(mimetype, data)
        return store

    def _write_store_data(self, fileobj):
        actual_data = {}
        for k, blob in self.items():
            actual_data[k] = {
                'type': blob.mimetype,
                'data': _base64_encode(blob.data),
            }

        with _io.TextIOWrapper(fileobj, encoding='utf-8') as text_stream:
            _json.dump(actual_data, text_stream)
