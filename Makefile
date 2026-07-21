#!/usr/bin/make

# SPDX-FileCopyrightText: 2026 SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
#
# SPDX-License-Identifier: Apache-2.0

test:
	pytest

coverage:
	pytest --cov=csaf_modifier
