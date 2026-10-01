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
    main,
)
from csaf_modifier.modifier import (build_notes, build_publisher, build_references,
                                    describe_changes)

BASIC = json_load((Path(__file__).parent / "csaf_documents/basic.json").open())


def test_basic():
    apply_always_changes(deepcopy(BASIC), None, "")


def test_empty():
    """
    Test the always-applied changes
    """
    doc, _ = apply_always_changes({}, None, "")
    tracking = doc["document"]["tracking"]
    assert tracking["version"] == "1"
    assert len(tracking["revision_history"]) == 1


def test_basepath_used_for_self_reference():
    """
    check that the self-reference is added, as first element of the array /document/references[].
    (CSAF spec 2.0 section 9.1.8)
    """
    # create some references
    parser = build_parser()
    args = parser.parse_args([
        "--reference-url", "https://example.com/advisory",
        "--reference-summary", "example advisory",
    ])
    doc = apply_references(deepcopy(BASIC), args)
    # add the self-reference
    doc, new_filename = apply_always_changes(doc, "https://example.com/csaf/", "doc.json")
    # assert the self-reference is the first one
    assert doc["document"]["references"] == [
        {
            "url": "https://example.com/csaf/" + new_filename.name,
            "summary": "reference to this modified document",
            "category": "self",
        },
        {
            "url": "https://example.com/advisory",
            "summary": "example advisory",
            "category": "external",
        }
    ]


def test_no_basepath_falls_back_to_bare_filename():
    doc, new_filename = apply_always_changes(deepcopy(BASIC), None, "doc.json")
    self_refs = [r for r in doc["document"]["references"] if r["category"] == "self"]
    assert self_refs[0]["url"] == new_filename.name


def test_describe_changes_without_arguments():
    parser = build_parser()
    assert describe_changes(parser.parse_args([])) == []


@pytest.mark.parametrize("argv,expected", [
    (["--note-text", "a"], ["1 note added"]),
    (["--note-text", "a", "--note-text", "b"], ["2 notes added"]),
    (["--reference-url", "https://example.com/", "--reference-summary", "s"],
     ["1 reference added"]),
    (["--legal-disclaimer", "text"], ["legal disclaimer set"]),
    (["--publisher-category", "vendor", "--publisher-name", "N",
      "--publisher-namespace", "https://example.com/"], ["publisher replaced"]),
])
def test_describe_changes(argv, expected):
    parser = build_parser()
    assert describe_changes(parser.parse_args(argv)) == expected


def test_describe_changes_order():
    parser = build_parser()
    args = parser.parse_args([
        "--publisher-category", "vendor",
        "--publisher-name", "N",
        "--publisher-namespace", "https://example.com/",
        "--note-text", "a", "--note-text", "b",
        "--legal-disclaimer", "text",
        "--reference-url", "https://example.com/", "--reference-summary", "s",
    ])
    assert describe_changes(args) == [
        "publisher replaced",
        "2 notes added",
        "legal disclaimer set",
        "1 reference added",
    ]


def test_revision_summary_fallbacks():
    parser = build_parser()
    doc, _ = apply_always_changes(deepcopy(BASIC), None, "doc.json",
                                  parser.parse_args([]))
    assert doc["document"]["tracking"]["revision_history"][-1]["summary"] \
        == "created a modified version from 1"


def test_apply_publisher_requires_all_mandatory_fields():
    parser = build_parser()
    args = parser.parse_args(["--publisher-name", "Foo"])
    with pytest.raises(argparse.ArgumentTypeError):
        doc = apply_publisher(deepcopy(BASIC), args)


@pytest.mark.parametrize("args", [
    # all of them raise ArgumentTypeError
    ["--publisher-name", "Foo"],
    ["--note-text", "t", "--note-category", "bogus"],
    ["--reference-url", "https://example.com/"],
])
def test_argument_errors(args, tmp_path, capsys, monkeypatch):
    """
    Argument errors should not result in an unhandled exception
    """
    doc = tmp_path / "in.json"
    doc.write_text("{}")
    monkeypatch.setattr("sys.argv",
                        ["csaf-modifier", str(doc), "--no-validation"] + args)

    with pytest.raises(SystemExit) as excinfo:
        main()

    # Exit code 2 are usage errors
    assert excinfo.value.code == 2
    assert "csaf-modifier: error:" in capsys.readouterr().err


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


def test_build_publisher_returns_none_without_parameters():
    parser = build_parser()
    assert build_publisher(parser.parse_args([])) is None


def test_build_publisher_mandatory_and_optional_parameters():
    parser = build_parser()
    args = parser.parse_args([
        "--publisher-category", "vendor",
        "--publisher-name", "Name",
        "--publisher-namespace", "https://example.com/",
        "--publisher-contact-details", "contact@example.com",
    ])
    assert build_publisher(args) == {
        "category": "vendor",
        "name": "Name",
        "namespace": "https://example.com/",
        "contact_details": "contact@example.com",
    }


def test_build_publisher_rejects_incomplete_parameters():
    parser = build_parser()
    args = parser.parse_args(["--publisher-name", "Name"])
    with pytest.raises(argparse.ArgumentTypeError):
        build_publisher(args)


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
