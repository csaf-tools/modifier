<!--
SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

SPDX-License-Identifier: Apache-2.0
-->

# CSAF Modifier Tool

CSAF modifier according to the specification: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#918-conformance-clause-8-csaf-modifier

## How it works

- Takes a CSAF document as input (file or stdin)
- accoding to user configuration it changes:
    - changes the publisher
    - adds notes
    - replaces the legal disclaimer
    - adds a new reference based on basepath and file name
- It always
    - changes the document tracking ID
    - adds a reference to the original CSAF document
- validates the conformity of the resulting modified CSAF document
- writes the result to the output file or stdout

## License

```
 SPDX-License-Identifier: Apache-2.0

 SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
 Software-Engineering: 2024 Intevation GmbH <https://intevation.de>
 ```
