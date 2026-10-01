# SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import json
import logging
from .validate import Validator, DEFAULT_ENDPOINT, DEFAULT_MODE, SUPPORTED_MODES, DEFAULT_PRESETS
from .modifier import (
    apply_always_changes,
    apply_legal_disclaimer,
    apply_notes,
    apply_publisher,
    apply_references,
    NOTE_CATEGORIES,
    REFERENCE_CATEGORIES,
)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(module)s - %(levelname)s - %(message)s')

PUBLISHER_CATEGORIES = ['coordinator', 'discoverer', 'other', 'translator', 'user', 'vendor']


def _write_csaf_doc(output_file, csaf_doc):
    json.dump(csaf_doc, output_file, indent=4, sort_keys=True)
    # write final line termination character, which json.dump does not,
    # but which is necessary to be a text file according to POSIX.
    output_file.write("\n")


def build_parser() -> argparse.ArgumentParser:
    """
    Separating the parser creation allows easier testing
    """
    parser = argparse.ArgumentParser(
        prog="csaf-modifier",
        description="Modify a CSAF document according to the CSAF 2.0 modifier conformance clause.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        type=argparse.FileType('rt'),
        help="Path to the input CSAF document (default: stdin)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        type=argparse.FileType('wt'),
        help="Path to write the modified CSAF document (default: stdout)",
    )
    parser.add_argument('--force', action='store_true',
                        help="If used, the converter produces output even if it is invalid "
                             "(errors occurred during modification). "
                             "Target use case: best-effort modification to JSON, "
                             "fix the errors manually, e.g. in Secvisogram.")
    parser.add_argument('--basepath',
                        help="Base URL to prefix the new document's filename with, used to "
                             "build the new self reference. If omitted, the bare filename "
                             "is used. Required for a valid document.")

    # Publisher
    parser.add_argument('--publisher-category', choices=PUBLISHER_CATEGORIES,
                        help="If set (together with --publisher-name and "
                             "--publisher-namespace), replaces document.publisher.")
    parser.add_argument('--publisher-name',
                        help="New publisher name.")
    parser.add_argument('--publisher-namespace',
                        help="New publisher namespace (URI).")
    parser.add_argument('--publisher-contact-details',
                        help="New publisher contact details.")
    parser.add_argument('--publisher-issuing-authority',
                        help="New publisher issuing authority.")

    # Notes
    parser.add_argument('--note-text', action='append', default=[], metavar="TEXT",
                        help="Add a note to document.notes with this text. Repeatable: "
                             "each occurrence starts a new note. If --note-category/"
                             "-title/-audience are used, they must be given exactly as "
                             "many times as --note-text, and are paired up by position.")
    parser.add_argument('--note-category', action='append', default=[], metavar="CATEGORY",
                        help=f"Category for the note at the same position as --note-text. "
                             f"Must be one of {NOTE_CATEGORIES}. Defaults to 'other'.")
    parser.add_argument('--note-title', action='append', default=[], metavar="TITLE",
                        help="Title for the note at the same position as --note-text.")
    parser.add_argument('--note-audience', action='append', default=[], metavar="AUDIENCE",
                        help="Audience for the note at the same position as --note-text.")
    parser.add_argument('--legal-disclaimer',
                        help="Replace the text of an existing legal_disclaimer note, "
                             "or add one if none exists.")

    # References
    parser.add_argument('--reference-url', action='append', default=[], metavar="URL",
                        help="Add an additional entry to document.references with this "
                             "URL. Repeatable: each occurrence starts a new reference "
                             "and requires a matching --reference-summary at the same "
                             "position.")
    parser.add_argument('--reference-summary', action='append', default=[], metavar="SUMMARY",
                        help="Summary for the reference at the same position as "
                             "--reference-url. Required, must match its count exactly.")
    parser.add_argument('--reference-category', action='append', default=[], metavar="CATEGORY",
                        help=f"Category for the reference at the same position as "
                             f"--reference-url. Must be one of {REFERENCE_CATEGORIES}. "
                             f"Defaults to 'external'.")

    # Validation
    parser.add_argument('--no-validation', action='store_true',
                        help="Deactivate validation by a validator service")
    parser.add_argument('--validator-endpoint',
                        default=DEFAULT_ENDPOINT,
                        help="The URL where the validator service is reachable. "
                             f"Default: {DEFAULT_ENDPOINT!r}.")
    parser.add_argument('--validator-mode',
                        default=DEFAULT_MODE,
                        help=f"The Validator mode, currently supported: "
                             f"{','.join(SUPPORTED_MODES)}. Default: {DEFAULT_MODE!r}.")
    parser.add_argument('--validator-preset',
                        default=DEFAULT_PRESETS,
                        help="One or more validation presets. Currently supported: "
                             "'schema', 'mandatory', 'optional', 'informative', 'basic', "
                             f"'extended', 'full'. Default: {''.join(DEFAULT_PRESETS)}.",
                             nargs='+')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    csaf_doc = json.load(args.input)
    filename = args.input.name if args.input.name != '<stdin>' else 'stdin.json'

    # for argument errors shows the message and the usage instead of a traceback
    try:
        new_csaf_doc, new_filename = apply_always_changes(csaf_doc, args.basepath,
                                                          filename, args)
        new_csaf_doc = apply_publisher(new_csaf_doc, args)
        new_csaf_doc = apply_notes(new_csaf_doc, args)
        new_csaf_doc = apply_references(new_csaf_doc, args)
        new_csaf_doc = apply_legal_disclaimer(new_csaf_doc, args)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    if not args.no_validation:
        validator = Validator(endpoint=args.validator_endpoint, mode=args.validator_mode,
                              presets=args.validator_preset)
        validation_result = validator.validate(new_csaf_doc)
        if not validation_result[0]:
            validator.log_result(validation_result[1], logging)
            if args.force:
                logging.warning("Some error occurred during validation,"
                                " but producing output as --force option is used.")
            else:
                logging.critical("Some error occurred during validation, can't produce output."
                                 " To override this, use --force.")
                sys.exit(1)
        else:
            logging.info("CSAF validation successful.")
    else:
        logging.info("CSAF validation skipped at user's request.")

    _write_csaf_doc(args.output, new_csaf_doc)


if __name__ == "__main__":
    sys.exit(main())
