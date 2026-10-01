<!--
SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

SPDX-License-Identifier: Apache-2.0
-->

# CSAF Modifier Tool

CSAF modifier according to the specification: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#918-conformance-clause-8-csaf-modifier

## How it works

- Takes a CSAF document as input (file or stdin)
- accoding to user configuration it applies:
    - change the publisher
    - add notes
    - replace the legal disclaimer
    - add new references
- It always
    - changes the document tracking ID
    - bumps the major version and adds a revision history entry
    - sets the status to `final` if the old version required a `draft` status
    - adds a reference to the original CSAF document as the first reference
    - converts the original self-reference into an external one
    - adds a new self-reference for the modified document
- Validates the conformity of the resulting modified CSAF document
- Writes the result to the output file or stdout

## Examples

### Set a new disclaimer:
```
$ csaf-modifier example.json --legal-disclaimer "This is the new disclaimer" | jq .document.notes[2]
{
  "category": "legal_disclaimer",
  "text": "This is the new disclaimer"
}
```
### Set the publisher:
```
$ csaf-modifier example.json --publisher-name 'New publisher' --publisher-category discoverer --publisher-contact-details discoverer@example.com --publisher-namespace https://example.com/ | jq .document.publisher
{
  "category": "discoverer",
  "contact_details": "discoverer@example.com",
  "name": "New publisher",
  "namespace": "https://example.com/"
}
```

## Usage

| Argument | Value | Description |
|----------|-------|-------------|
| `-h` or `--help` | - | show help on usage and available arguments |

### Input and Output

Both the input and the output CSAF document can be either files or stdin/stdout.

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| positional | `-` (stdin) | Input file name | Path to the input CSAF document |
| `-o` or `--output` | `-` (stdout) | Output file name | Path to write the modified CSAF document |

### Document status

The status handling needs no configuration.

The CSAF specification requires the status `draft` for version specifications with with major version `0` and pre-release versions (CSAF 2.0 specification sections 3.1.11.1 and 3.1.11.2).
With the automatic increament of the major version, a document may loose the requirement for the `draft` state.
Then the status is set to `final`.

| Old version | Old status | New version | New status |
|-------------|------------|-------------|------------|
| `0`         | `draft`    | `1`         | `final`    |
| `0.1.0`     | `draft`    | `1.1.0`     | `final`    |
| `1.0.0-rc1` | `draft`    | `2.0.0-rc1` | `draft`    |
| `2`         | `draft`    | `3`         | `draft`    |
| `1`         | `interim`  | `2`         | `interim`  |

### Reference handling

The reference handling needs no configuration.

For example, when the input document has the self-reference `https://example.com/csaf/orig.json`, then the resulting document has the following reference changes:

| Position | Category | URL |
|----------|----------|-----|
| first | `external` | `https://example.com/csaf/orig.json` (the original self-reference) |
| last | `self` | `https://example.com/csaf/csaf-modifier-<date>-<filename>` (the new self-reference) |

The new self-reference URL is derived from the original self-reference's path.

If the input document has no self-reference, the CSAF modifier logs a warning and leaves
`/document/references[]` unchanged.

### CSAF validation

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--force` | - | False | If used, the converter produces output even if it is invalid (errors occurred during modification). Target use case: best-effort modification to JSON, fix the errors manually, e.g. in Secvisogram |
| `--no-validation` | - | - | Deactivate validation by a validator service |
| `--validator-endpoint` | URL | `http://localhost:8082/api/v1/validate` | The URL where the validator service is reachable |
| `--validator-mode` | mode | `secvisogram` | The Validator mode, currently supported: secvisogram |
| `--validator-preset` | preset | `basic` | One or more validation presets. Currently supported: 'schema', 'mandatory', 'optional', 'informative', 'basic', 'extended', 'full' |

### Publisher

If the publisher is to be set, category, name and namespace are required.
Contact details and issuing authority are optional.

| Argument | Value | Required | Description |
|----------|-------|----------|-------------|
| `--publisher-category` | One of coordinator,discoverer,other,translator,user,vendor | Yes |New publisher category |
| `--publisher-name` | PUBLISHER_NAME | Yes | New publisher name |
| `--publisher-namespace` | PUBLISHER_NAMESPACE | Yes | New publisher namespace (URI) |
| `--publisher-contact-details` | PUBLISHER_CONTACT_DETAILS | No | New publisher contact details |
| `--publisher-issuing-authority` | PUBLISHER_ISSUING_AUTHORITY | No | New publisher issuing authority |

### Notes

Repeatable: each occurrence of `--note-text` starts a new note.
If `--note-category`/`--note-title`/`--note-audience` are used, they must be given exactly as many times as `--note-text`, and are paired up by position.

| Argument | Value | Required | Description |
|----------|-------|----------|-------------|
| `--note-text` | TEXT | Yes | Add a note to document.notes with this text
| `--note-title` | TITLE | No | Title for the note at the same position as `--note-text` |
| `--note-audience` | AUDIENCE | No | Audience for the note at the same position as `--note-text` |
| `--note-category` | One of 'description', 'details', 'faq', 'general', 'other', 'summary' | No, default: `other` | Category for the note |
| `--legal-disclaimer` | Text | No | Replace the text of an existing legal_disclaimer note, or add one if none exists |

### References

Repeatable: each occurrence of `--reference-url` starts a new reference and requires a matching `--reference-summary` at the same position.

| Argument | Value | Required | Description |
|----------|-------|----------|-------------|
| `--reference-url` | URL | Yes | Add an additional entry to `document.references` with this URL |
| `--reference-summary` | Text | Yes | Summary for the reference at the same position as `--reference-url` |
| `--reference-category` | one of 'external', 'self' | No, default: `external` | Category for the reference at the same position as `--reference-url` |


## License

```
 SPDX-License-Identifier: Apache-2.0

 SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
 Software-Engineering: 2024 Intevation GmbH <https://intevation.de>
 ```
