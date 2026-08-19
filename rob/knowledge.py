"""Reference sources: official ServiceNow documentation and the Best Practices Library.

Two problems this solves.

1. D-015 requires every rule to cite a PRIMARY source. ServiceNow publishes its
   product documentation as markdown at github.com/ServiceNow/ServiceNowDocs,
   refreshed monthly, with a canonical_url per page. That is the primary source,
   machine-readable, so citing it becomes a lookup rather than a research task.

2. A finding says what is wrong and how to fix it. It does not say where to read
   more. Linking a finding to the official page, and to the relevant Best
   Practices Library asset where one exists, turns a report into something a
   platform team can act on without a second search.

Design constraints that shaped this:

- NO RUNTIME DEPENDENCY ON EITHER SOURCE. The docs repo is 360 MB and 50,000
  files; the BPL library is 9.5 GB. Both are indexed once into a compact JSON
  file, and ROB reads only that. A scan must not need a clone or a login.
- SEARCH IS EXPLAINABLE. Scoring is a declared weight per field, not a black
  box, because a citation a reviewer cannot check is worth nothing.
- COPYRIGHT. The index stores titles, descriptions and links. It never copies
  document or deck content. BPL assets are ServiceNow copyright behind a login:
  ROB points at them, it does not reproduce them.
"""
from __future__ import annotations

import gzip
import json
import math
import pathlib
import re
from dataclasses import asdict, dataclass, field

# Words too common in this domain to carry signal. "servicenow" matches everything.
STOPWORDS = frozenset("""
a an the and or of to in on for with without is are be as by from at into this that
servicenow now platform instance record records table tables field fields
sys has ref new use using can may all any one two per via etc
""".split())

# Field weights. Declared here so a reviewer can see why a result ranked.
WEIGHTS = {"title": 4, "area": 2, "description": 1}

# Best Practices Library titles are mostly genre labels: "Process Guide",
# "Workshop Presentation", "Deep Dive", "Starter Stories". Those words matched
# almost any query and put a Security Incident deck under an admin-role finding.
# They describe the format of an asset, not its subject.
BPL_FORMAT_WORDS = frozenset("""
management process guide guides guidance workshop presentation overview
introduction intro starter stories story deep dive best practices practice
playbook deck kit toolkit template templates example examples success pack
value framework implementation adoption journey roadmap accelerator
""".split())

SOURCE_STOPWORDS = {"best-practices-library": BPL_FORMAT_WORDS}

# Tuned against the real indexes: 49,983 documentation pages and 999 BPL assets.
# High enough that one shared common word cannot carry a citation, low enough
# that a single rare, on-topic term still can.
MIN_SCORE = 12.0

# Two distinct title terms must match. With 50,000 documentation pages, one
# shared word is a coincidence rather than a topic.
MIN_TITLE_TERMS = 2

# ...unless that one word is rare enough to be the subject itself: present in
# this share of entries or fewer. A share rather than a score, so it means the
# same thing in a 60-entry index and a 50,000-entry one.
RARE_TERM_SHARE = 0.01

# Indexes are gzipped: the docs index is 26 MB of JSON and 3 MB compressed, and
# it is read once per scan. Both extensions are accepted on load, so an index
# built by an older version still works.
DOCS_INDEX_NAME = "servicenow_docs_index.json.gz"
BPL_INDEX_NAME = "bpl_index.json.gz"
INDEX_NAMES = (
    DOCS_INDEX_NAME, BPL_INDEX_NAME,
    "servicenow_docs_index.json", "bpl_index.json",
)


def _write_index(path: str | pathlib.Path, payload: dict) -> None:
    path = pathlib.Path(path)
    raw = json.dumps(payload).encode()
    if path.suffix == ".gz":
        path.write_bytes(gzip.compress(raw, 6))
    else:
        path.write_bytes(raw)


def _read_index(path: str | pathlib.Path) -> dict:
    path = pathlib.Path(path)
    raw = path.read_bytes()
    if path.suffix == ".gz" or raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return json.loads(raw)


@dataclass
class Reference:
    source: str          # "servicenow-docs" | "best-practices-library"
    title: str
    url: str
    area: str = ""
    description: str = ""
    local_path: str = ""  # BPL only, where a downloaded file exists
    score: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def terms_of(text: str, extra_stopwords: frozenset = frozenset()) -> list[str]:
    """Split into terms, expanding identifiers into their parts.

    A finding's affected area is usually a table name, and the table name is the
    topic: `cmdb_ci_win_server` should match documentation about the CMDB, and
    `sys_user_has_role` should match documentation about roles. Treating the
    identifier as one opaque token threw that away, which left ROB's own
    category labels doing the topical work instead.
    """
    blocked = STOPWORDS | extra_stopwords
    out = []
    for token in re.split(r"[^a-z0-9_.]+", (text or "").lower()):
        if not token:
            continue
        # Customer-specific identifiers are names, not topics. `u_vendor_contracts`
        # was matching documentation about vendor contract management, which has
        # nothing to do with a missing ACL on someone's custom table.
        if token.startswith(("u_", "x_")):
            continue
        if len(token) > 2 and token not in blocked:
            out.append(_singular(token))
        if "_" in token or "." in token:
            out.extend(_singular(part) for part in re.split(r"[_.]+", token)
                       if len(part) > 2 and part not in blocked)
    return out


def _singular(term: str) -> str:
    """Fold a trailing plural s.

    Without it "Migrate Legacy Workflows to Flows and Playbooks" did not match a
    finding about legacy Workflow usage, which is the single best citation the
    Best Practices Library has for that finding. Deliberately not a stemmer:
    over-stemming makes citations wrong in ways that are hard to see, and the
    only mismatch worth fixing here is the plural.
    """
    if len(term) > 4 and term.endswith("s") and not term.endswith(("ss", "us", "is")):
        return term[:-1]
    return term


# --------------------------------------------------------------------------- index building


def _frontmatter(text: str) -> dict:
    """Parse the small, predictable YAML header. Not a general YAML parser, on
    purpose: pulling in a dependency for six known keys is a bad trade."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    out = {}
    for line in text[3:end].splitlines():
        if ":" not in line or line.startswith(" "):
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def build_docs_index(repo: str | pathlib.Path, out_path: str | pathlib.Path, branch: str = "australia") -> dict:
    """Index a ServiceNowDocs clone. Titles and links only, never content."""
    repo = pathlib.Path(repo)
    md_root = repo / "markdown"
    if not md_root.is_dir():
        raise FileNotFoundError(
            f"{repo} does not look like a ServiceNowDocs clone (no markdown/ directory). "
            "Clone it with: git clone --depth 1 https://github.com/ServiceNow/ServiceNowDocs"
        )
    entries, skipped = [], 0
    for path in sorted(md_root.rglob("*.md")):
        try:
            head = path.read_text(errors="replace")[:2000]
        except OSError:
            skipped += 1
            continue
        fm = _frontmatter(head)
        title = fm.get("title")
        if not title:
            skipped += 1
            continue
        rel = path.relative_to(repo).as_posix()
        entries.append({
            "title": title,
            "url": fm.get("canonical_url") or
                   f"https://raw.githubusercontent.com/ServiceNow/ServiceNowDocs/{branch}/{rel}",
            "area": (fm.get("breadcrumb") or "").strip("[]").replace(",", " >"),
            "description": (fm.get("description") or "")[:200],
            "topic_type": fm.get("topic_type", ""),
            "publication": rel.split("/")[1] if "/" in rel else "",
        })
    payload = {"source": "servicenow-docs", "branch": branch, "count": len(entries), "entries": entries}
    _write_index(out_path, payload)
    return {"indexed": len(entries), "skipped": skipped, "out": str(out_path)}


def _assets_of(data):
    """Accept the shapes a catalog can plausibly take.

    The BPL harvester writes a dict with a list inside, but a hand-trimmed
    export is just as likely to be a list, or a dict keyed by asset id. Being
    strict here would mean a confusing failure over a formatting detail.
    """
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("assets", "items", "records"):
        if isinstance(data.get(key), list):
            return [d for d in data[key] if isinstance(d, dict)]
    nested = next((v for v in data.values() if isinstance(v, list) and v and isinstance(v[0], dict)), None)
    if nested:
        return nested
    values = [v for v in data.values() if isinstance(v, dict)]
    return values if len(values) == len(data) else []


def build_bpl_index(catalog: str | pathlib.Path, out_path: str | pathlib.Path,
                    files_root: str | pathlib.Path | None = None,
                    files_prefix: str = "") -> dict:
    """Index a BPL-Scraper catalog.json. Metadata and links only, never deck content."""
    catalog = pathlib.Path(catalog)
    data = json.loads(catalog.read_text())
    items = _assets_of(data)
    if not items:
        raise ValueError(
            f"No assets found in {catalog}. Expected a list of assets, a dict with an asset list, "
            "or a dict keyed by asset id."
        )
    files_root = pathlib.Path(files_root) if files_root else None
    entries = []
    for item in items:
        if not isinstance(item, dict):
            continue
        title = item.get("title") or item.get("name")
        if not title:
            continue
        suites = item.get("productSuites") or ""
        entry = {
            "title": title,
            "url": (f"https://mynow.servicenow.com/now/best-practices/asset/{item['sysId']}"
                    if item.get("sysId") else ""),
            "area": (suites if isinstance(suites, str) else " ".join(map(str, suites)))
                    or item.get("category", ""),
            "description": (item.get("description") or "")[:200],
            "format": item.get("fileFormat", ""),
            "identifier": item.get("humanReadableIdentifier", ""),
        }
        if files_root and files_root.is_dir():
            stem = re.sub(r"[^A-Za-z0-9]+", " ", title).strip()
            match = next((p for p in files_root.rglob("*") if p.is_file()
                          and re.sub(r"[^A-Za-z0-9]+", " ", p.stem).strip().lower() == stem.lower()), None)
            if match:
                # files_prefix rewrites the recorded root, for when the index is
                # built somewhere the library is mounted and read somewhere it
                # is not, which is the normal case for a VPS.
                entry["local_path"] = (
                    str(pathlib.Path(files_prefix) / match.relative_to(files_root))
                    if files_prefix else str(match)
                )
        entries.append(entry)
    payload = {"source": "best-practices-library", "count": len(entries), "entries": entries}
    _write_index(out_path, payload)
    return {"indexed": len(entries), "with_local_file": sum(1 for e in entries if e.get("local_path")),
            "out": str(out_path)}


# --------------------------------------------------------------------------- searching


@dataclass
class Index:
    source: str
    entries: list[dict] = field(default_factory=list)
    _idf: dict = field(default_factory=dict, repr=False)
    _df: dict = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, path: str | pathlib.Path) -> "Index":
        data = _read_index(path)
        index = cls(source=data.get("source", "unknown"), entries=data.get("entries", []))
        index.build_idf()
        return index

    def build_idf(self) -> None:
        """Weight terms by how rare they are in this index.

        Stopword lists could not fix the real problem: "security" appears in a
        fifth of the Best Practices Library, so a single shared word was enough
        to cite a Security Incident deck under an admin-role finding. It is not
        a word to ban either, because it is genuinely the subject of some
        assets. Rarity settles it without a list to maintain: a term that
        appears everywhere contributes almost nothing, and one that appears
        twice contributes a lot.
        """
        extra = SOURCE_STOPWORDS.get(self.source, frozenset())
        total = len(self.entries) or 1
        df: dict[str, int] = {}
        for e in self.entries:
            seen = set()
            for field_name in WEIGHTS:
                seen |= set(terms_of(e.get(field_name, ""), extra))
            for term in seen:
                df[term] = df.get(term, 0) + 1
        # Smoothed, so a term present in every entry still scores something and a
        # three-entry index does not collapse to all-zeros.
        self._idf = {t: math.log((total + 1) / (1 + c)) + 1 for t, c in df.items()}
        self._df = df

    def idf(self, term: str) -> float:
        # An unseen term cannot match anything, so this default never applies.
        return self._idf.get(term, math.log(len(self.entries) + 1) + 1)

    def is_rare(self, term: str) -> bool:
        """Rare enough to be a topic on its own.

        Expressed as a share of the index rather than an IDF value, because IDF
        scales with corpus size: a threshold calibrated on 999 Best Practices
        assets silently excluded everything in a smaller index.
        """
        return self._df.get(term, 0) <= max(1, RARE_TERM_SHARE * len(self.entries))

    def search(self, query: str, limit: int = 3, min_score: float = MIN_SCORE) -> list[Reference]:
        """Rank by rare, on-topic terms, and require the title to match.

        Each query term is counted once, at the best field weight it achieves.
        Counting a term again for appearing in both the title and the area was
        what let one common word clear the bar twice, which is how a Security
        Incident deck ended up cited under an admin-role finding.

        A title hit is still required. A citation that is merely topical costs a
        reader more than no citation, because they have to open it to find out.
        """
        extra = SOURCE_STOPWORDS.get(self.source, frozenset())
        wanted = set(terms_of(query, extra))
        if not wanted:
            return []
        scored = []
        for e in self.entries:
            fields = {name: set(terms_of(e.get(name, ""), extra)) for name in WEIGHTS}
            title_hits = wanted & fields["title"]
            # Two distinct title terms, or one rare enough to be a topic on its
            # own. A single common word is a coincidence ("country" matched an AI
            # Search language form against a missing-ACL finding), but a single
            # rare one is the whole subject: "skipped" is exactly what an
            # unresolved-skipped-records finding is about.
            if not title_hits:
                continue
            if len(title_hits) < MIN_TITLE_TERMS and not any(self.is_rare(t) for t in title_hits):
                continue
            score = 0.0
            for term in wanted:
                weights = [w for name, w in WEIGHTS.items() if term in fields[name]]
                if weights:
                    score += max(weights) * self.idf(term)
            if score >= min_score:
                scored.append((score, e))
        scored.sort(key=lambda pair: (-pair[0], pair[1]["title"]))
        return [
            Reference(source=self.source, title=e["title"], url=e.get("url", ""), area=e.get("area", ""),
                      description=e.get("description", ""), local_path=e.get("local_path", ""), score=round(s, 1))
            for s, e in scored[:limit]
        ]


class KnowledgeBase:
    """Whatever reference indexes this workspace has. Absent indexes are not an
    error: ROB works without them, it just says less."""

    def __init__(self, home: str | pathlib.Path):
        self.home = pathlib.Path(home)
        self.indexes: list[Index] = []
        seen: set[str] = set()
        for name in INDEX_NAMES:
            path = self.home / name
            if not path.exists():
                continue
            try:
                index = Index.load(path)
            except (json.JSONDecodeError, OSError, gzip.BadGzipFile):
                continue
            if index.source in seen:  # prefer the gz form, ignore a stale plain copy
                continue
            seen.add(index.source)
            self.indexes.append(index)

    @property
    def available(self) -> list[str]:
        return [i.source for i in self.indexes]

    def search(self, query: str, limit_per_source: int = 2) -> list[Reference]:
        out = []
        for index in self.indexes:
            out.extend(index.search(query, limit=limit_per_source))
        return out

    def for_finding(self, finding: dict, limit_per_source: int = 2) -> list[Reference]:
        """Reference material for one finding.

        The query is built from what the rule already declares rather than from
        a new field nobody would maintain: its title, its affected area and its
        basis references, which name the practice the rule encodes.
        """
        topics = finding.get("doc_topics") or []
        if topics:
            # The rule said what it is about, in ServiceNow's vocabulary. Its
            # title is written for a human reading a report, and searching with
            # that matched "always" and "true" from "always-true ACLs".
            query = " ".join(topics)
        else:
            query = " ".join(p for p in (finding.get("title", ""), finding.get("affected_area", "")) if p)
        return self.search(query, limit_per_source=limit_per_source)
