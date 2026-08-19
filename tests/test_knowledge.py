"""Reference source tests: ServiceNow docs and the Best Practices Library.

Three properties matter more than search quality:
  - ROB works fine with no indexes at all
  - the index stores links and metadata, never document or deck content
  - scoring is explainable, so a citation can be checked
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from rob.knowledge import (
    _read_index,
    BPL_INDEX_NAME,
    DOCS_INDEX_NAME,
    WEIGHTS,
    Index,
    KnowledgeBase,
    build_bpl_index,
    build_docs_index,
    terms_of,
)

DOC = """---
title: Instance security hardening settings
description: Properties that harden an instance, with baseline values per release.
canonical_url: https://www.servicenow.com/docs/r/platform-security/hardening.html
topic_type: reference
breadcrumb: [Reference, Platform security, Hardening]
---

# Body text that must never reach the index
Secret internal prose, paragraphs of it, all copyrighted.
"""

OTHER = """---
title: CMDB health dashboard
description: Completeness, compliance and correctness scoring for the CMDB.
canonical_url: https://www.servicenow.com/docs/r/cmdb/health.html
breadcrumb: [Concept, CMDB]
---
More body text.
"""


@pytest.fixture
def docs_repo(tmp_path):
    root = tmp_path / "ServiceNowDocs" / "markdown" / "platform-security"
    root.mkdir(parents=True)
    (root / "hardening.md").write_text(DOC)
    other = tmp_path / "ServiceNowDocs" / "markdown" / "cmdb"
    other.mkdir(parents=True)
    (other / "health.md").write_text(OTHER)
    (tmp_path / "ServiceNowDocs" / "markdown" / "cmdb" / "no-frontmatter.md").write_text("# nothing")
    return tmp_path / "ServiceNowDocs"


# --- building ----------------------------------------------------------------

def test_docs_index_captures_metadata_and_links(docs_repo, tmp_path):
    out = tmp_path / DOCS_INDEX_NAME
    stats = build_docs_index(docs_repo, out)
    assert stats["indexed"] == 2 and stats["skipped"] == 1
    entries = _read_index(out)["entries"]
    hardening = next(e for e in entries if "hardening" in e["title"].lower())
    assert hardening["url"].startswith("https://www.servicenow.com/docs/")
    assert "Platform security" in hardening["area"]


def test_docs_index_never_copies_document_body(docs_repo, tmp_path):
    """Copyright: ROB points at documentation, it does not reproduce it."""
    out = tmp_path / DOCS_INDEX_NAME
    build_docs_index(docs_repo, out)
    raw = json.dumps(_read_index(out))
    assert "Secret internal prose" not in raw
    assert "Body text that must never reach the index" not in raw


def test_a_wrong_directory_says_what_to_do(tmp_path):
    with pytest.raises(FileNotFoundError) as exc:
        build_docs_index(tmp_path, tmp_path / "x.json")
    assert "git clone" in str(exc.value)


def test_bpl_index_captures_metadata_and_finds_local_files(tmp_path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({
        "a1": {"title": "CMDB Health - Deep Dive", "sysId": "abc123",
               "description": "How to run CMDB health remediation.",
               "productSuites": "IT Operations Management", "fileFormat": "Microsoft PowerPoint"},
        "a2": {"title": "Hardware Asset Management - Intro", "sysId": "def456",
               "description": "HAM basics.", "productSuites": "IT Asset Management"},
    }))
    files = tmp_path / "files" / "ITOM"
    files.mkdir(parents=True)
    (files / "CMDB Health - Deep Dive.pptx").write_text("deck bytes")
    stats = build_bpl_index(catalog, tmp_path / BPL_INDEX_NAME, tmp_path / "files")
    assert stats["indexed"] == 2 and stats["with_local_file"] == 1
    entries = _read_index(tmp_path / BPL_INDEX_NAME)["entries"]
    deck = next(e for e in entries if "Deep Dive" in e["title"])
    assert deck["url"].endswith("abc123") and deck["local_path"].endswith(".pptx")


def test_bpl_index_never_copies_deck_content(tmp_path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps([{"title": "T", "sysId": "s", "description": "d"}]))
    build_bpl_index(catalog, tmp_path / BPL_INDEX_NAME)
    assert "deck bytes" not in json.dumps(_read_index(tmp_path / BPL_INDEX_NAME))


# --- searching ---------------------------------------------------------------

def test_search_ranks_by_declared_field_weights(docs_repo, tmp_path):
    build_docs_index(docs_repo, tmp_path / DOCS_INDEX_NAME)
    index = Index.load(tmp_path / DOCS_INDEX_NAME)
    hits = index.search("instance security hardening settings")
    assert hits and "hardening" in hits[0].title.lower()
    assert hits[0].score >= WEIGHTS["title"], "a title match must outweigh a description match"


def test_stopwords_do_not_match_everything(docs_repo, tmp_path):
    """'servicenow' and 'platform' appear in every page. If they scored, every
    query would return the same three results."""
    assert "servicenow" not in terms_of("ServiceNow platform instance records")
    build_docs_index(docs_repo, tmp_path / DOCS_INDEX_NAME)
    assert Index.load(tmp_path / DOCS_INDEX_NAME).search("servicenow platform instance") == []


def test_weak_matches_are_dropped(docs_repo, tmp_path):
    build_docs_index(docs_repo, tmp_path / DOCS_INDEX_NAME)
    assert Index.load(tmp_path / DOCS_INDEX_NAME).search("entirely unrelated quantum ferret") == []


# --- integration -------------------------------------------------------------

def test_rob_works_with_no_indexes(tmp_path):
    kb = KnowledgeBase(tmp_path)
    assert kb.available == [] and kb.search("anything") == []
    assert kb.for_finding({"title": "x", "affected_area": "y"}) == []


def test_a_corrupt_index_is_skipped_not_fatal(tmp_path):
    (tmp_path / DOCS_INDEX_NAME).write_bytes(b"{not gzip or json")
    assert KnowledgeBase(tmp_path).available == []


def test_for_finding_builds_its_query_from_the_finding(docs_repo, tmp_path):
    build_docs_index(docs_repo, tmp_path / DOCS_INDEX_NAME)
    kb = KnowledgeBase(tmp_path)
    refs = kb.for_finding({
        "title": "Security hardening properties deviating from baseline",
        "affected_area": "sys_properties", "category": "Security"})
    assert refs and "hardening" in refs[0].title.lower()


def test_technical_report_gains_further_reading_when_a_kb_exists(docs_repo, tmp_path):
    from rob.cli import load_snapshot
    from rob.engine import run_scan
    from rob.report import technical_report

    build_docs_index(docs_repo, tmp_path / DOCS_INDEX_NAME)
    result = run_scan(load_snapshot(str(pathlib.Path(__file__).parent.parent / "fixtures" / "pdi_like_snapshot.json")), {})
    without = technical_report(result)
    with_kb = technical_report(result, KnowledgeBase(tmp_path))
    assert "Further reading" not in without, "no index, no change to the report"
    assert "Further reading" in with_kb
    assert "servicenow.com/docs" in with_kb


def test_agent_findings_carry_references_when_available(docs_repo, tmp_path):
    from rob.agent import Orchestrator
    from rob.cli import load_snapshot
    from rob.engine import run_scan
    from rob.store import connect, store_run

    build_docs_index(docs_repo, tmp_path / DOCS_INDEX_NAME)
    con = connect(tmp_path / "rob_history.db")
    run_id = store_run(con, run_scan(load_snapshot(
        str(pathlib.Path(__file__).parent.parent / "fixtures" / "pdi_like_snapshot.json")), {}))
    orch = Orchestrator(tmp_path, bytes.fromhex("ab" * 32), {})
    res = orch.findings(run_id)
    assert res.ok
    cited = [f for f in res.data["findings"] if f.get("references")]
    assert cited, "a finding about hardening should cite the hardening page"
    assert cited[0]["references"][0]["url"].startswith("https://")


def test_index_round_trips_through_gzip(docs_repo, tmp_path):
    """26 MB of JSON compresses to 3 MB and is read once per scan. Both forms
    load, so an index built by an older version still works."""
    gz, plain = tmp_path / "a.json.gz", tmp_path / "b.json"
    build_docs_index(docs_repo, gz)
    build_docs_index(docs_repo, plain)
    assert gz.read_bytes()[:2] == b"\x1f\x8b"
    assert Index.load(gz).entries == Index.load(plain).entries


def test_a_stale_plain_index_does_not_duplicate_a_gz_one(docs_repo, tmp_path):
    build_docs_index(docs_repo, tmp_path / DOCS_INDEX_NAME)
    build_docs_index(docs_repo, tmp_path / "servicenow_docs_index.json")
    assert KnowledgeBase(tmp_path).available == ["servicenow-docs"]


def test_a_common_word_cannot_carry_a_citation_but_a_rare_one_can(tmp_path):
    """The real Best Practices Library failure, reproduced at a scale where term
    rarity means something.

    "security" appears in a fifth of the library, so a single shared word was
    enough to cite a Security Incident deck under an admin-role finding. Banning
    the word was wrong, because it is genuinely the subject of some assets.
    Rarity settles it. A two-entry corpus cannot demonstrate this: IDF has
    nothing to weigh, which is why this fixture is deliberately larger.
    """
    assets = [{"title": f"Security Operations Capability {i}", "sysId": f"s{i}",
               "description": "Security guidance."} for i in range(40)]
    assets += [{"title": f"Employee Onboarding Journey {i}", "sysId": f"e{i}",
                "description": "Onboarding guidance."} for i in range(19)]
    assets.append({"title": "CMDB Health Ownership Remediation", "sysId": "c1",
                   "description": "Improving CMDB ownership and staleness."})
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(assets))
    build_bpl_index(catalog, tmp_path / BPL_INDEX_NAME)
    index = Index.load(tmp_path / BPL_INDEX_NAME)

    # "security" is in 40 of 60 titles: common, so it must not be enough alone.
    assert index.search("Direct admin role assignment to users Security") == []
    # "cmdb" and "ownership" are rare and both in the title: that is a topic,
    # not a coincidence.
    hits = index.search("CI ownership coverage below threshold cmdb_ci CMDB")
    assert hits and "CMDB" in hits[0].title


def test_a_term_matching_two_fields_is_counted_once(tmp_path):
    """Counting a term again for appearing in both title and area let one common
    word clear the bar twice."""
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(
        [{"title": f"Security Thing {i}", "sysId": str(i), "productSuites": "Security Operations",
          "description": "Security."} for i in range(50)]))
    build_bpl_index(catalog, tmp_path / BPL_INDEX_NAME)
    assert Index.load(tmp_path / BPL_INDEX_NAME).search("Security") == []


def test_local_paths_can_be_recorded_under_a_different_root(tmp_path):
    """Built where the library is mounted, read where it is not."""
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps([{"title": "CMDB Health Deep Dive", "sysId": "a", "description": "d"}]))
    files = tmp_path / "mnt" / "BPL" / "ITOM"
    files.mkdir(parents=True)
    (files / "CMDB Health Deep Dive.pptx").write_text("x")
    build_bpl_index(catalog, tmp_path / BPL_INDEX_NAME, tmp_path / "mnt" / "BPL",
                    files_prefix="/Users/rob/Documents/BPL-Scraper/library/files")
    entry = _read_index(tmp_path / BPL_INDEX_NAME)["entries"][0]
    assert entry["local_path"] == "/Users/rob/Documents/BPL-Scraper/library/files/ITOM/CMDB Health Deep Dive.pptx"


def test_bpl_genre_words_do_not_drive_a_match(tmp_path):
    """'Process Guide' and 'Workshop Presentation' describe an asset's format,
    not its subject. They matched almost any query until they were excluded."""
    from rob.knowledge import BPL_FORMAT_WORDS, terms_of

    assert "management" in BPL_FORMAT_WORDS and "workshop" in BPL_FORMAT_WORDS
    assert terms_of("Major Security Incident Management - Process Guide", BPL_FORMAT_WORDS) == \
        ["major", "security", "incident"]

    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps([
        {"title": "Major Security Incident Management - Process Guide", "sysId": "a", "description": ""},
        {"title": "Security Posture Control (SPC) - Workshop Presentation", "sysId": "b", "description": ""},
        {"title": "CMDB Health - Deep Dive", "sysId": "c", "description": "CMDB ownership and staleness."},
    ]))
    build_bpl_index(catalog, tmp_path / BPL_INDEX_NAME)
    index = Index.load(tmp_path / BPL_INDEX_NAME)
    assert index.search("Direct admin role assignment to users Security") == []
    assert index.search("Security hardening properties deviating from baseline") == []
    hit = index.search("CI ownership coverage cmdb_ci CMDB health")
    assert hit and "CMDB" in hit[0].title


def test_table_names_are_read_as_topics():
    """A finding's affected area is usually a table name, and the table name is
    the topic. Treating it as one opaque token threw that away."""
    from rob.knowledge import terms_of

    assert set(terms_of("cmdb_ci_win_server")) >= {"cmdb", "win", "server", "cmdb_ci_win_server"}
    assert "role" in terms_of("sys_user_has_role")
    assert "sys" not in terms_of("sys_user_has_role"), "three-letter noise stays out"


def test_rob_category_labels_do_not_steer_the_search(docs_repo, tmp_path):
    """'Technical Debt' is ROB's taxonomy. Including it pulled a business-rule
    finding toward Technical Risk Management documentation."""
    build_docs_index(docs_repo, tmp_path / DOCS_INDEX_NAME)
    kb = KnowledgeBase(tmp_path)
    with_category = {"title": "CMDB health dashboard", "affected_area": "cmdb_ci",
                     "category": "Completely Irrelevant Label"}
    assert kb.for_finding(with_category), "the category must neither help nor hurt"
    assert all("Irrelevant" not in r.title for r in kb.for_finding(with_category))


def test_customer_table_names_are_not_topics(docs_repo, tmp_path):
    """`u_vendor_contracts` is someone's table name. It was matching
    documentation about vendor contract management, which has nothing to do
    with a missing ACL on a custom table."""
    from rob.knowledge import terms_of

    assert terms_of("u_vendor_contracts") == []
    assert terms_of("x_acme_custom_thing") == []
    assert "cmdb" in terms_of("cmdb_ci_win_server"), "platform tables are still topics"


def test_a_trailing_plural_does_not_break_a_match():
    """"Migrate Legacy Workflows to Flows and Playbooks" is the single best
    reference for a legacy Workflow finding, and it did not match."""
    from rob.knowledge import terms_of

    assert terms_of("workflows") == terms_of("workflow")
    assert terms_of("records") == terms_of("record")
    assert terms_of("process") == ["process"], "not a stemmer: 'process' must survive intact"
    assert terms_of("status") == ["status"]


def test_one_rare_word_is_a_topic_but_one_common_word_is_not(tmp_path):
    """"skipped" appears in a handful of assets and is the whole subject of an
    unresolved-skipped-records finding. "security" appears everywhere."""
    assets = [{"title": f"Security Operations Capability {i}", "sysId": f"s{i}", "description": ""}
              for i in range(60)]
    assets.append({"title": "Skipped Log Review Playbook", "sysId": "k", "description": ""})
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(assets))
    build_bpl_index(catalog, tmp_path / BPL_INDEX_NAME)
    index = Index.load(tmp_path / BPL_INDEX_NAME)

    hits = index.search("Unresolved skipped records from previous upgrades")
    assert hits and "Skipped" in hits[0].title, "one rare word is enough"
    assert index.search("Direct admin role assignment to users Security") == [], \
        "one common word is not"


def test_every_rule_declares_what_it_is_about():
    """A rule title is written for a human reading a report. Searching with it
    matched documentation on the words 'always' and 'true'."""
    from rob.rules import RULE_REGISTRY

    missing = sorted(rid for rid, rule in RULE_REGISTRY.items() if not rule.DOC_TOPICS)
    assert not missing, f"rules with no declared topics: {missing}"


def test_declared_topics_are_preferred_over_the_title(docs_repo, tmp_path):
    build_docs_index(docs_repo, tmp_path / DOCS_INDEX_NAME)
    kb = KnowledgeBase(tmp_path)
    finding = {"title": "Tables without ACLs or with always-true ACLs",
               "affected_area": "u_vendor_contracts",
               "doc_topics": ["CMDB health dashboard", "CMDB completeness"]}
    refs = kb.for_finding(finding)
    assert refs and "CMDB" in refs[0].title, "the declared topics decide, not the prose"
