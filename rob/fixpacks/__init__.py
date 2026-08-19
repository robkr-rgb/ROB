"""Fix-pack generators, keyed by rule ID.

Each generator returns a FixPack satisfying the five-element contract in
recommendations/remediation-framework.md, or None when a safe fix cannot be
derived from evidence (honest solvability: never overstate).
Fix artefacts are executor-neutral: a human, a gated API writer or a scoped
app executor can apply them identically.
"""
from .sec003 import generate as sec003
from .cmdb004 import generate as cmdb004
from .sec001 import generate as sec001
from .cmdb_packs import cmdb001, cmdb003, cmdb005, cmdb006
from .td_sec_packs import td001, td002, td003, sec002, cmdb002

FIXPACK_GENERATORS = {
    "ROB-TD-001": td001,
    "ROB-TD-002": td002,
    "ROB-TD-003": td003,
    "ROB-SEC-001": sec001,
    "ROB-SEC-002": sec002,
    "ROB-SEC-003": sec003,
    "ROB-CMDB-001": cmdb001,
    "ROB-CMDB-002": cmdb002,
    "ROB-CMDB-003": cmdb003,
    "ROB-CMDB-004": cmdb004,
    "ROB-CMDB-005": cmdb005,
    "ROB-CMDB-006": cmdb006,
}
