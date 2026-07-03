# SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
#
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from json import load as json_load

from csaf_modifier.cli import modify1

BASIC = json_load((Path(__file__).parent / "csaf_documents/basic.json").open())

EMPTY = {
    "document": {
        "publisher": {},
        "tracking": {
            "id": "1",
            "version": "1",
            "revision_history": []
        },
        "references": [],
    },
    "references": {},
}


def test_basic():
    modify1(BASIC, "", 1)


def test_empty():
    modify1(EMPTY, "", 1)
