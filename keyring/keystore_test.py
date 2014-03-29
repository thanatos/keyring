import os
import tempfile
import unittest

import keystore


class KeystoreTest(unittest.TestCase):
    def tearDown(self):
        if self.temp_file is not None:
            os.unlink(self.temp_file.name)
        super(KeystoreTest, self).tearDown()

    def test_keystore(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.close()

        blob_a = keystore.DataBlob('text/plain', b'Hello World.')
        blob_b = keystore.DataBlob('application/json', b'{"hello": "world"}')

        keystore_data = {
            "a": blob_a,
            "b": blob_b,
        }

        keystore.write_keystore(self.temp_file.name, 'hunter2', keystore_data)

        keystore_data = keystore.read_keystore(self.temp_file.name, 'hunter2')

        self.assertEqual(set(('a', 'b')), set(keystore_data.keys()))
        self.assertEqual(blob_a, keystore_data['a'])
        self.assertEqual(blob_b, keystore_data['b'])


if __name__ == '__main__':
    unittest.main()
