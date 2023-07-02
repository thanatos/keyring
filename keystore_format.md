# Keystore File Format

The format is designed to be recoverable by hand. That is, in the case that my
entire compute setup burns down in a fire, I can still decrypt the file.

The keystore is, roughly, a ZIP file encrypted with `age`. Each item is
represented as a file in the ZIP.


## The ZIP layer

As stated above, the result after being decrpyted by `age` is a ZIP file. The
ZIP has two special, required entries:

* `META-INF/MAGIC`: This contains the static string
  `application/prs.thanatos.keyring`, and identifies this file as a keyring.
* `META-INF/CONTENTS`: This contains the "contents" of the keyring; this holds
  only what items are on the keyring, and metadata about those items. The
  actual data is in other, separate files in the ZIP.

The items themselves are under `items/`.

## The `META-INF/CONTENTS` file

This file is a JSON file containing the metadata for items on the keyring. It
looks like,

```json
{
	"item-a": {"type": "application/prs.thanatos.keyring.password+json"},
	"item-b": {
		"type": "application/prs.thanatos.keyring.password+json",
		"hidden": true
	}
}
```

The outer mapping is a name of item → item metadata mapping. The metadata has
two attributes:

* `type`: the mimetype of the item
* `hidden`: (optional; defaults to false) a bool specifying if this item should
  not show up by default in listings or selection prompts.

See `spec/contents.json-schema.yaml` for a JSONSchema.


# Login Password Format

This format has a mimetype of `application/prs.thanatos.keyring.password+json`.

This format is JSON data; it a single password, e.g., for a website.

```
{
    "username": "bob",
    "email": "bob@example.com",
    "password": "hunter2",
    "security_questions": [
        {
            "q": "What is your dog's name?",
            "a": "Fido",
        }
    ],
}
```

All top level keys are optional, except `password`. Items in
`security_questions` must have exactly `q` and `a`, whose values are strings.
