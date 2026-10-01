# SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
#
# SPDX-License-Identifier: Apache-2.0

from argparse import ArgumentTypeError, Namespace
from datetime import datetime, timezone
from logging import getLogger
from .utils import next_major_revision, rfc3339now, version_forces_draft
from pathlib import Path

logger = getLogger(__name__)


NOTE_CATEGORIES = ['description', 'details', 'faq', 'general', 'other', 'summary']
REFERENCE_CATEGORIES = ['external', 'self']


def apply_always_changes(csaf_doc: dict, filename: str) -> (dict, str):
    """
    Applies the changes that are always made to a csaf document:
    bump the tracking id & version and rotate the references

    Handling follows CSAF spec section 9.1.8.

    References:
    - "includes a reference to the original advisory as first element of the array /document/references[]."
    - Change the original self-reference to an external reference
    - Add a new self-reference for the modified document, based on the original self-reference URL

    Tracking ID:
    - "does not have the same /document/tracking/id as the original document."
    - A document without an ID gets a new one based on the current date and time.

    Status:
    - A "draft" only required by the old version becomes "final" when the
      version increment leaves that state. Any other status is left unchanged.
    """
    # for easier access
    d = csaf_doc.get("document", {})

    now = rfc3339now()

    # prefix for new id and filename
    id_prefix = "csaf-modifier-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M-")

    # tracking section: bump version
    dt = d.get("tracking", {})
    old_id = dt.get("id")
    # new id should not use the old id as prefix, so use it as postfix
    # without an old id just use the generated prefix
    new_id = id_prefix + old_id if old_id else id_prefix[:-1]

    old_version = dt.get("version")
    new_version = next_major_revision(old_version)

    dt["current_release_date"] = now
    dt["id"] = new_id
    if "revision_history" not in dt:
        dt["revision_history"] = []
    dt["revision_history"].append({
        "date": now,
        "number": new_version,
        "summary": "created a modified version from " + (old_id or "an id-less document"),
        })

    # Bump the status to "final" if draft is no longer required by the version number
    if dt.get("status") == "draft" \
            and version_forces_draft(old_version) \
            and not version_forces_draft(new_version):
        dt["status"] = "final"
    dt["version"] = new_version

    new_filename = Path(filename).parent / Path(id_prefix + Path(filename).name)

    # make sure "references" exists
    if "references" not in d:
        d["references"] = []

    original_self_ref = next((ref for ref in d["references"]
                               if ref.get("category") == "self"), None)
    if original_self_ref:
        # fallback to empty string, resulting in just the filename
        original_url = original_self_ref.get("url", "")
        original_self_ref["category"] = "external"
        # insert the reference to the original advisory at the start
        d["references"].insert(0, {
            "category": "external",
            "summary": "original document before modification",
            })
        if original_url:
            d["references"][0]["url"] = original_url
        # add a new self-reference for the modified document itself
        d["references"].append({
            "category": "self",
            "summary": "Reference to this document",
            "url": f"{original_url.rsplit('/', 1)[0]}/{new_filename.name}",
            })
    else:
        logger.warning("Input document has no 'self' reference. "
                        "Cannot add a reference to the original advisory "
                        "as required by the CSAF modifier conformance clause.")

    return csaf_doc, new_filename


def apply_publisher(csaf_doc: dict, args: Namespace) -> dict:
    """
    Modifies document.publisher
    """
    if not (args.publisher_category and args.publisher_name and args.publisher_namespace):
        if args.publisher_category or args.publisher_name or args.publisher_namespace:\
            raise ArgumentTypeError(
                "All of --publisher-category, --publisher-name and --publisher-namespace "
                "must be given, if one of them is given")
        # none of the parameters given
        return csaf_doc

    publisher = {
        "category": args.publisher_category,
        "name": args.publisher_name,
        "namespace": args.publisher_namespace,
        }
    if args.publisher_contact_details:
        publisher["contact_details"] = args.publisher_contact_details
    if args.publisher_issuing_authority:
        publisher["issuing_authority"] = args.publisher_issuing_authority

    csaf_doc.setdefault("document", {})["publisher"] = publisher
    return csaf_doc


def build_notes(args: Namespace) -> list:
    """
    Parses notes from --note-text plus paired --note-category/
    --note-title/--note-audience

    Each --note-text starts a new note
    If --note-category/-title/-audience are given, their count must match --note-text's count exactly
    The values are paired up by position.
    """
    texts = args.note_text or []
    paired = {
        'category': args.note_category or [],
        'title': args.note_title or [],
        'audience': args.note_audience or [],
        }
    for field, values in paired.items():
        if values and len(values) != len(texts):
            raise ArgumentTypeError(
                f"--note-{field} was given {len(values)} time(s) but --note-text "
                f"was given {len(texts)} time(s). The count must match.")

    notes = []
    for i, text in enumerate(texts):
        note = {"category": paired['category'][i] if paired['category'] else 'other',
                "text": text}
        if paired['title']:
            note["title"] = paired['title'][i]
        if paired['audience']:
            note["audience"] = paired['audience'][i]
        if note["category"] not in NOTE_CATEGORIES:
            raise ArgumentTypeError(
                f"invalid note category {note['category']!r}, must be one of {NOTE_CATEGORIES}")
        notes.append(note)
    return notes


def apply_notes(csaf_doc: dict, args: Namespace) -> dict:
    """
    Adds document.notes
    """
    notes = build_notes(args)
    if not notes:
        return csaf_doc

    d = csaf_doc.setdefault("document", {})
    d.setdefault("notes", []).extend(notes)
    return csaf_doc


def build_references(args: Namespace) -> list:
    """
    Parses references from --reference-url plus paired --reference-summary/
    --reference-category

    Each --reference-url starts a new reference.
    --reference-summary is required and must match --reference-url's count
    exactly.
    --reference-category is optional but if given must also match.
    Defaults to 'external'. The values are paired up by position.
    """
    urls = args.reference_url or []
    summaries = args.reference_summary or []
    categories = args.reference_category or []

    if len(urls) != len(summaries):
        raise ArgumentTypeError(
            f"--reference-summary was given {len(summaries)} time(s) but "
            f"--reference-url was given {len(urls)} time(s). The count must match.")
    if categories and len(categories) != len(urls):
        raise ArgumentTypeError(
            f"--reference-category was given {len(categories)} time(s) but "
            f"--reference-url was given {len(urls)} time(s). The count must match.")

    references = []
    for i, url in enumerate(urls):
        category = categories[i] if categories else 'external'
        if category not in REFERENCE_CATEGORIES:
            raise ArgumentTypeError(
                f"Invalid reference category {category!r}. "
                f"Must be one of {REFERENCE_CATEGORIES}")
        references.append({"category": category, "summary": summaries[i], "url": url})
    return references


def apply_references(csaf_doc: dict, args: Namespace) -> dict:
    """
    Adds additional entries to document.references
    """
    references = build_references(args)
    if not references:
        return csaf_doc

    d = csaf_doc.setdefault("document", {})
    d.setdefault("references", []).extend(references)
    return csaf_doc


def apply_legal_disclaimer(csaf_doc: dict, args: Namespace) -> dict:
    """
    Modifies legal_disclaimer in document.notes
    Special variant of a note
    """
    if not args.legal_disclaimer:
        return csaf_doc

    d = csaf_doc.setdefault("document", {})
    notes = d.setdefault("notes", [])
    for note in notes:
        if note.get("category") == "legal_disclaimer":
            note["text"] = args.legal_disclaimer
            return csaf_doc

    notes.append({"category": "legal_disclaimer", "text": args.legal_disclaimer})
    return csaf_doc


