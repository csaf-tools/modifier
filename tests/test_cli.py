# SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
#
# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy
from pathlib import Path
from json import load as json_load
import argparse

import pytest

from csaf_modifier.cli import (
    apply_always_changes,
    apply_legal_disclaimer,
    apply_notes,
    apply_publisher,
    apply_references,
    build_parser,
)
from csaf_modifier.modifier import build_notes, build_references

BASIC = json_load((Path(__file__).parent / "csaf_documents/basic.json").open())


def test_basic():
    apply_always_changes(deepcopy(BASIC), None, "")


def test_empty():
    apply_always_changes({}, None, "")


def test_basepath_used_for_self_reference():
    doc, new_filename = apply_always_changes(deepcopy(BASIC), "https://example.com/csaf/", "doc.json")
    refs = doc["document"]["references"]
    self_refs = [r for r in refs if r["category"] == "self"]
    assert len(self_refs) == 1
    assert self_refs[0]["url"] == "https://example.com/csaf/" + new_filename.name


def test_no_basepath_falls_back_to_bare_filename():
    doc, new_filename = apply_always_changes(deepcopy(BASIC), None, "doc.json")
    self_refs = [r for r in doc["document"]["references"] if r["category"] == "self"]
    assert self_refs[0]["url"] == new_filename.name


def test_apply_publisher_requires_all_mandatory_fields():
    parser = build_parser()
    args = parser.parse_args(["--publisher-name", "Foo"])
    doc = apply_publisher(deepcopy(BASIC), args)
    assert doc["document"]["publisher"] == BASIC["document"]["publisher"]


def test_apply_publisher_overrides_when_complete():
    parser = build_parser()
    args = parser.parse_args([
        "--publisher-category", "vendor",
        "--publisher-name", "Foo",
        "--publisher-namespace", "https://foo.example",
    ])
    doc = apply_publisher(deepcopy(BASIC), args)
    assert doc["document"]["publisher"] == {
        "category": "vendor",
        "name": "Foo",
        "namespace": "https://foo.example",
        }


def test_apply_notes_appends():
    parser = build_parser()
    args = parser.parse_args([
        "--note-text", "hello, world, with commas",
        "--note-category", "general",
    ])
    doc = apply_notes(deepcopy(BASIC), args)
    notes = doc["document"]["notes"]
    assert notes[-1] == {"text": "hello, world, with commas", "category": "general"}


def test_apply_notes_multiple_paired_by_position():
    parser = build_parser()
    args = parser.parse_args([
        "--note-text", "first", "--note-category", "general",
        "--note-text", "second", "--note-category", "faq",
    ])
    doc = apply_notes(deepcopy(BASIC), args)
    notes = doc["document"]["notes"]
    assert notes[-2:] == [
        {"text": "first", "category": "general"},
        {"text": "second", "category": "faq"},
        ]


def test_apply_legal_disclaimer_adds_when_absent():
    parser = build_parser()
    args = parser.parse_args(["--legal-disclaimer", "some disclaimer"])
    doc = apply_legal_disclaimer(deepcopy(BASIC), args)
    disclaimers = [n for n in doc["document"]["notes"] if n["category"] == "legal_disclaimer"]
    assert len(disclaimers) == 1
    assert disclaimers[0]["text"] == "some disclaimer"


def test_apply_legal_disclaimer_replaces_when_present():
    doc = deepcopy(BASIC)
    doc["document"].setdefault("notes", []).append({"category": "legal_disclaimer", "text": "old"})

    parser = build_parser()
    args = parser.parse_args(["--legal-disclaimer", "new disclaimer"])
    doc = apply_legal_disclaimer(doc, args)

    disclaimers = [n for n in doc["document"]["notes"] if n["category"] == "legal_disclaimer"]
    assert len(disclaimers) == 1
    assert disclaimers[0]["text"] == "new disclaimer"


def test_build_notes_defaults_category():
    parser = build_parser()
    args = parser.parse_args(["--note-text", "hello"])
    assert build_notes(args) == [{"text": "hello", "category": "other"}]


def test_build_notes_rejects_mismatched_counts():
    parser = build_parser()
    args = parser.parse_args([
        "--note-text", "first", "--note-text", "second",
        "--note-category", "general",
    ])
    with pytest.raises(argparse.ArgumentTypeError):
        build_notes(args)


def test_build_notes_rejects_unknown_category():
    parser = build_parser()
    args = parser.parse_args(["--note-text", "hello", "--note-category", "bogus"])
    with pytest.raises(argparse.ArgumentTypeError):
        build_notes(args)


def test_apply_references_appends():
    """
    simple succeeding example
    """
    parser = build_parser()
    args = parser.parse_args([
        "--reference-url", "https://example.com/advisory",
        "--reference-summary", "example advisory",
    ])
    doc = apply_references(deepcopy(BASIC), args)
    refs = doc["document"]["references"]
    assert refs[-1] == {
        "category": "external",
        "summary": "example advisory",
        "url": "https://example.com/advisory",
        }


def test_apply_references_multiple_paired_by_position():
    """
    Two references, 3 arguments each
    """
    parser = build_parser()
    args = parser.parse_args([
        "--reference-url", "https://example.com/a", "--reference-summary", "A",
        "--reference-category", "external",
        "--reference-url", "https://example.com/b", "--reference-summary", "B",
        "--reference-category", "self",
    ])
    doc = apply_references(deepcopy(BASIC), args)
    refs = doc["document"]["references"]
    assert refs[-2:] == [
        {"category": "external", "summary": "A", "url": "https://example.com/a"},
        {"category": "self", "summary": "B", "url": "https://example.com/b"},
        ]


def test_build_references_requires_matching_summary_count():
    """
    missing reference summary
    """
    parser = build_parser()
    args = parser.parse_args(["--reference-url", "https://example.com/a"])
    with pytest.raises(argparse.ArgumentTypeError):
        build_references(args)


def test_build_references_invalid_unknown_category():
    parser = build_parser()
    args = parser.parse_args([
        "--reference-url", "https://example.com/a",
        "--reference-summary", "A",
        "--reference-category", "eve",
    ])
    with pytest.raises(argparse.ArgumentTypeError):
        build_references(args)
