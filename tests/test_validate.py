# SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
#
# SPDX-License-Identifier: Apache-2.0

from json import load
from pathlib import Path

from csaf_modifier.validate import Validator


INCOMPLETE_DOCUMENT = {
    "document": {
        "csaf_version": "2.0",
        "category": "category",
        "title": "title",
        "publisher": {
            "category": "vendor",
            "name": "name",
            "namespace": "https://example.com",
        },
        "tracking": {
            "current_release_date": "2025-01-01T00:00:00.000+00:00",
            "initial_release_date": "2025-01-01T00:00:00.000+00:00",
            "id": "0",
            "revision_history": [
                {
                    "date": "2025-01-01T00:00:00.000+00:00",
                    "number": "0",
                    "summary": "text",
                }
            ],
            "status": "final",
            "version": "0",
        },
    }
}


def test_validator_incomplete():
    """
    a minimal, basically empty document that validates
    """
    validator = Validator()
    result = validator.validate(INCOMPLETE_DOCUMENT)
    assert result[0] is False
    assert 'Connection reset by peer' not in result[1]
    assert len(result[1]) > 0


def test_validator_basic():
    BASIC = load((Path(__file__).parent /
                  "csaf_documents/basic.json").open())
    validator = Validator()
    result = validator.validate(BASIC)
    assert result[0] is True
    assert result[1] == []
