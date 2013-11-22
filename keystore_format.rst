====================
Keystore File Format
====================

The Outer Layer
===============

The keystore's most outer format is a simple key-value store. The values are
binary blobs, the keys are Unicode strings.

This key-value mapping is stored as a JSON mapping. The keys (strings), are
left as is, the values describe the type and content associated with that key.
Data (the binary blob itself) is base64 encoded and stored as JSON strings.

As an example, a UTF-8 encoded "world" might be stored in the key "hello" like
this::

    {
        "hello": {"type": "text/plain; charset=utf-8", "data": "d29ybGQ="}
    }

Here, ``type`` is the mimetype of the data in ``data``. ``data`` is base64
encoded.

This mapping is then:

1. JSON encoded.
2. Gzip'd.
3. Encrypted using GPG, using a symmetric cipher, password only.
4. Written to disk.


Login Credential Format
=======================

This blob shows up as ``application/json+login; charset=utf-8``. (Charset can
theoretically be different, but it is recommended to use UTF-8.)

This format is JSON data. The outer key is a name; the blob is the login
details for that entity, stored as a JSON mapping. The mapping is indexed by an
alias for the login, the key being the credentials.

::

    "foo's login": {
        "username": "foo",
        "password": "hunter2"
    }

The key ``username`` is allowed to be ``email``, if that is more applicable. E.g.,

::

    "foo's login": {
        "email": "foo@example.com",
        "password": "hunter2"
    }

An example of multiple logins:

::

    "foo's login": {
        "username": "foo",
        "password": "hunter2"
    },
    "bar's login": {
        "username": "bar",
        "password": "hunter3"
    }
