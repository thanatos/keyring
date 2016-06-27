import abc as _abc
import gzip as _gzip


class Keystore(metaclass=_abc.ABCMeta):
    @classmethod
    def read(cls, decrypted_fileobj):
        with cls._decompress(decrypted_fileobj) as decompressed_fileobj:
            return cls._read_store_data(decompressed_fileobj)

    @classmethod
    @_abc.abstractmethod
    def _read_store_data(cls, fileobj):
        raise NotImplementedError()

    @staticmethod
    def _decompress(decrypted_fileobj):
        return _gzip.GzipFile(fileobj=decrypted_fileobj, mode='rb')

    def write(self, fileobj):
        """Write the store object into the passed file.

        This method does ***not*** encrypt. (That is handled at a higher
        layer.)
        """
        with self._compress(fileobj) as compressing_fileobj:
            self._write_store_data(compressing_fileobj)

    @_abc.abstractmethod
    def _write_store_data(self, fileobj):
        """Write the raw, uncompressed data for the keystore.
        
        The output of this function is automatically compressed by the default
        implementation of write. (This can be avoided by overriding both this
        and write, or overriding ``_compress``.)
        """
        raise NotImplementedError()

    @staticmethod
    def _compress(outer_fileobj):
        return _gzip.GzipFile(fileobj=outer_fileobj, mode='wb')


class Item(object):
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
