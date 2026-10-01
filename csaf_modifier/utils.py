# SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
#
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
from re import compile as re_compile

VERSION_INT_REGEXP = re_compile(r'^(0|[1-9][0-9]*)$') # from CSAF 2.0 3.1.11.1

VERSION_SEMVER_REGEXP = re_compile(
    r'^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$')  # from https://semver.org/ 2.2 FAQ


def next_major_revision(last_revision_number: str = '0') -> str:
    """
    >>> next_major_revision('3')
    '4'
    >>> next_major_revision('1.12.3')
    '2.12.3'
    >>> next_major_revision('0.0.100-pre10+build2')
    '1.0.100-pre10+build2'
    """
    if not last_revision_number:
        last_revision_number = '0'
    if VERSION_INT_REGEXP.fullmatch(last_revision_number):
        return str(int(last_revision_number) + 1)

    m = VERSION_SEMVER_REGEXP.match(last_revision_number)
    return str(int(m.group("major")) + 1) + m.string[m.start("minor") - 1:]


def rfc3339now():
    """
    Return now() as rfc3339 in UTC without microseconds
    """
    # CSAF wants the "Z" suffix, isoformat() writes the offset as "+00:00"
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace("+00:00", "Z")
