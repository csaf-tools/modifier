# SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
#
# SPDX-License-Identifier: Apache-2.0

from argparse import ArgumentTypeError, Namespace
from datetime import datetime
from uuid import uuid4
from .utils import next_major_revision, rfc3339now
from pathlib import Path


NOTE_CATEGORIES = ['description', 'details', 'faq', 'general', 'other', 'summary']
REFERENCE_CATEGORIES = ['external', 'self']


def apply_always_changes(csaf_doc: dict, basepath: str, filename: str) -> (dict, str):
    """
    Applies the changes that are always made to a csaf document:
    bump the tracking id & version and rotate the references
    """
    d = csaf_doc.setdefault("document", {})

    now = rfc3339now()

    # prefix for new id and filename
    id_prefix = "csaf-modifier-" + datetime.utcnow().strftime("%Y%m%d-%H%M-")

    # tracking section: bump version
    dt = d.setdefault("tracking", {})
    old_id = dt.get("id", str(uuid4()))
    new_id = id_prefix + old_id

    new_version = next_major_revision(dt.get("version"))

    dt["current_release_date"] = now
    dt["id"] = new_id
    if "revision_history" not in dt:
        dt["revision_history"] = []
    dt["revision_history"].append({
        "date": now,
        "number": new_version,
        "summary": "created a modified version from " + old_id,
        })
    dt["status"] = "final"  # we are at least version 1 so we must be final
    dt["version"] = new_version

    new_filename = Path(filename).parent / Path(id_prefix + Path(filename).name)

    # make sure "references" exists
    if "references" not in d:
        d["references"] = []
    # move self references to external and invent new self
    for ref in d["references"]:
        if ref["category"] == "self":
            ref["category"] = "external"
            ref["summary"] = "original " + ref["summary"]

    reference_filename = new_filename.name
    reference_url = (basepath + reference_filename) if basepath else reference_filename
    # insert self-reference as first element (CSAF spec 2.0 section 9.1.8)
    d["references"].insert(0, {
        "category": "self",
        "summary": "reference to this modified document",
        "url": reference_url,
        })

    return csaf_doc, new_filename


def build_publisher(args: Namespace) -> dict:
    """
    Parses the publisher from --publisher-category, --publisher-name and
    --publisher-namespace plus the optional --publisher-contact-details and
    --publisher-issuing-authority

    Returns None if no publisher parameter is given.
    All three mandatory parameters must be given, if one of them is given.
    """
    if not (args.publisher_category and args.publisher_name and args.publisher_namespace):
        if args.publisher_category or args.publisher_name or args.publisher_namespace:
            raise ArgumentTypeError(
                "All of --publisher-category, --publisher-name and --publisher-namespace "
                "must be given, if one of them is given")
        # none of the parameters given
        return None

    publisher = {
        "category": args.publisher_category,
        "name": args.publisher_name,
        "namespace": args.publisher_namespace,
        }
    if args.publisher_contact_details:
        publisher["contact_details"] = args.publisher_contact_details
    if args.publisher_issuing_authority:
        publisher["issuing_authority"] = args.publisher_issuing_authority
    return publisher


def apply_publisher(csaf_doc: dict, args: Namespace) -> dict:
    """
    Modifies document.publisher
    """
    publisher = build_publisher(args)
    if not publisher:
        return csaf_doc

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


