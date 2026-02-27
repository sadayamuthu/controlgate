# Gates 9–18 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 10 new security gates (deps, api, privacy, resilience, incident, observability, memsafe, license, aiml, container) to ControlGate, expanding from 8 to 18 gates.

**Architecture:** Each gate is a standalone file following the identical `BaseGate` + `_PATTERNS` contract used by all existing gates. Each gate is wired into `catalog.py` (`GATE_CONTROL_MAP`) and `gates/__init__.py` (`ALL_GATES`) immediately when created. No changes to `engine.py`, `base.py`, `models.py`, or reporters.

**Tech Stack:** Python 3.10+, pytest, re (stdlib). No new dependencies.

---

## Context: How Gates Work

Read these files before starting:
- `src/controlgate/gates/base.py` — abstract `BaseGate` class with `_make_finding()` helper
- `src/controlgate/gates/secrets_gate.py` — canonical example gate (pattern + scan loop)
- `tests/test_gates/test_secrets_gate.py` — canonical test pattern
- `src/controlgate/catalog.py` — `GATE_CONTROL_MAP` that must be updated per gate
- `src/controlgate/gates/__init__.py` — `ALL_GATES` list that must be updated per gate

The `_make_finding(control_id, file, line, description, evidence, remediation)` helper looks up severity and `non_negotiable` from the NIST catalog. If the control_id isn't in the catalog it falls back to `"MEDIUM"` severity — this is acceptable.

**Run tests with:** `pytest tests/ -v` (requires virtualenv with `pip install -e ".[dev]"`)

---

## Task 1: Dependency Vulnerability Gate (`deps`)

**Files:**
- Create: `src/controlgate/gates/deps_gate.py`
- Create: `tests/test_gates/test_deps_gate.py`
- Modify: `src/controlgate/catalog.py` (add to `GATE_CONTROL_MAP`)
- Modify: `src/controlgate/gates/__init__.py` (add to `ALL_GATES`)

### Step 1: Write the failing test

Create `tests/test_gates/test_deps_gate.py`:

```python
"""Tests for the Dependency Vulnerability Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.deps_gate import DepsGate


@pytest.fixture
def gate(catalog):
    return DepsGate(catalog)


_NO_VERIFY_DIFF = """\
diff --git a/Makefile b/Makefile
--- a/Makefile
+++ b/Makefile
@@ -1,3 +1,4 @@
 install:
+\tpip install --no-verify requests
"""

_IGNORE_SCRIPTS_DIFF = """\
diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -1,3 +1,4 @@
+  "install": "npm install --ignore-scripts"
"""

_HTTP_REGISTRY_DIFF = """\
diff --git a/.npmrc b/.npmrc
--- /dev/null
+++ b/.npmrc
@@ -0,0 +1,1 @@
+registry=http://registry.npmjs.org/
"""

_UNPINNED_PIP_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,3 @@
+FROM python:3.11
+RUN pip install requests flask
+CMD ["python", "app.py"]
"""

_CLEAN_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,3 @@
+FROM python:3.11
+RUN pip install requests==2.31.0 flask==3.0.0
+CMD ["python", "app.py"]
"""


class TestDepsGate:
    def test_detects_no_verify(self, gate):
        diff_files = parse_diff(_NO_VERIFY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("no-verify" in f.description.lower() or "integrity" in f.description.lower() for f in findings)

    def test_detects_ignore_scripts(self, gate):
        diff_files = parse_diff(_IGNORE_SCRIPTS_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_http_registry(self, gate):
        diff_files = parse_diff(_HTTP_REGISTRY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("http" in f.description.lower() for f in findings)

    def test_detects_unpinned_pip_install(self, gate):
        diff_files = parse_diff(_UNPINNED_PIP_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_pinned_install_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_NO_VERIFY_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "deps"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_NO_VERIFY_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"RA-5", "SI-2", "SA-12"}
        for f in findings:
            assert f.control_id in valid_ids
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_gates/test_deps_gate.py -v
```

Expected: `ModuleNotFoundError: No module named 'controlgate.gates.deps_gate'`

### Step 3: Implement `deps_gate.py`

Create `src/controlgate/gates/deps_gate.py`:

```python
"""Gate 9 — Dependency Vulnerability Gate.

Detects dependency hygiene violations that indicate vulnerability risk:
bypassed integrity checks, unpinned runtime installs, and insecure registry URLs.

NIST Controls: RA-5, SI-2, SA-12
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""--no-verify"""),
        "Package integrity verification bypassed with --no-verify",
        "SA-12",
        "Remove --no-verify to ensure package checksums are validated",
    ),
    (
        re.compile(r"""--ignore-scripts"""),
        "npm --ignore-scripts bypasses postinstall security hooks",
        "SA-12",
        "Audit dependencies manually before using --ignore-scripts; prefer a scanned internal registry",
    ),
    (
        re.compile(r"""http://[^\s]*(?:pypi|npmjs|rubygems|packagist|pkg\.go\.dev|registry\.)"""),
        "Insecure HTTP URL used for package registry — man-in-the-middle risk",
        "SI-2",
        "Use HTTPS for all package registry URLs",
    ),
    (
        re.compile(r"""pip\s+install\s+(?!-r\s)(?:[A-Za-z0-9][A-Za-z0-9_.-]*)(?:\s+[A-Za-z0-9][A-Za-z0-9_.-]*)*\s*$"""),
        "pip install without pinned version — dependency may resolve to a vulnerable release",
        "RA-5",
        "Pin all dependencies to exact versions (pip install package==1.2.3) or use a lockfile",
    ),
]


class DepsGate(BaseGate):
    """Gate 9: Detect dependency vulnerability hygiene violations."""

    name = "Dependency Vulnerability Gate"
    gate_id = "deps"
    mapped_control_ids = ["RA-5", "SI-2", "SA-12"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                for pattern, description, control_id, remediation in _PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            self._make_finding(
                                control_id=control_id,
                                file=diff_file.path,
                                line=line_no,
                                description=description,
                                evidence=line.strip()[:120],
                                remediation=remediation,
                            )
                        )
        return findings
```

### Step 4: Wire gate into catalog and __init__

In `src/controlgate/catalog.py`, add to `GATE_CONTROL_MAP`:
```python
    "deps":          ["RA-5", "SI-2", "SA-12"],
```

In `src/controlgate/gates/__init__.py`, add import and list entry:
```python
from controlgate.gates.deps_gate import DepsGate
# add DepsGate to ALL_GATES list and __all__
```

### Step 5: Run tests to verify they pass

```bash
pytest tests/test_gates/test_deps_gate.py -v
```

Expected: All tests PASS (note: `test_pinned_install_no_findings` may need pattern tuning if false-positives appear — adjust the pip pattern to require `==` absence check).

### Step 6: Commit

```bash
git add src/controlgate/gates/deps_gate.py tests/test_gates/test_deps_gate.py \
        src/controlgate/catalog.py src/controlgate/gates/__init__.py
git commit -m "feat: add Gate 9 — Dependency Vulnerability gate (deps, RA-5/SI-2/SA-12)"
```

---

## Task 2: API Security Gate (`api`)

**Files:**
- Create: `src/controlgate/gates/api_gate.py`
- Create: `tests/test_gates/test_api_gate.py`
- Modify: `src/controlgate/catalog.py`
- Modify: `src/controlgate/gates/__init__.py`

### Step 1: Write the failing test

Create `tests/test_gates/test_api_gate.py`:

```python
"""Tests for the API Security Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.api_gate import APIGate


@pytest.fixture
def gate(catalog):
    return APIGate(catalog)


_VERIFY_FALSE_DIFF = """\
diff --git a/client.py b/client.py
--- a/client.py
+++ b/client.py
@@ -1,3 +1,4 @@
 import requests
+response = requests.get("https://api.example.com", verify=False)
"""

_CORS_ALL_DIFF = """\
diff --git a/settings.py b/settings.py
--- /dev/null
+++ b/settings.py
@@ -0,0 +1,2 @@
+CORS_ORIGIN_ALLOW_ALL = True
+ALLOWED_HOSTS = ["*"]
"""

_API_KEY_QUERY_DIFF = """\
diff --git a/api.py b/api.py
--- a/api.py
+++ b/api.py
@@ -1,3 +1,4 @@
+url = f"https://api.example.com/data?api_key={key}&format=json"
"""

_CREDENTIALED_CORS_DIFF = """\
diff --git a/headers.py b/headers.py
--- /dev/null
+++ b/headers.py
@@ -0,0 +1,2 @@
+response.headers["Access-Control-Allow-Origin"] = "*"
+response.headers["Access-Control-Allow-Credentials"] = "true"
"""

_GRAPHQL_INTROSPECTION_DIFF = """\
diff --git a/schema.py b/schema.py
--- /dev/null
+++ b/schema.py
@@ -0,0 +1,2 @@
+app.add_url_rule("/graphql", view_func=GraphQLView.as_view("graphql", schema=schema, graphiql=True))
+GRAPHQL_INTROSPECTION = True
"""

_CLEAN_DIFF = """\
diff --git a/client.py b/client.py
--- /dev/null
+++ b/client.py
@@ -0,0 +1,3 @@
+import requests
+response = requests.get("https://api.example.com")
+assert response.status_code == 200
"""


class TestAPIGate:
    def test_detects_verify_false(self, gate):
        diff_files = parse_diff(_VERIFY_FALSE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("verify" in f.description.lower() or "tls" in f.description.lower() for f in findings)

    def test_detects_cors_allow_all(self, gate):
        diff_files = parse_diff(_CORS_ALL_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_api_key_in_query(self, gate):
        diff_files = parse_diff(_API_KEY_QUERY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_credentialed_cors(self, gate):
        diff_files = parse_diff(_CREDENTIALED_CORS_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_clean_code_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_VERIFY_FALSE_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "api"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_VERIFY_FALSE_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"SC-8", "AC-3", "SC-5", "SI-10"}
        for f in findings:
            assert f.control_id in valid_ids
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_gates/test_api_gate.py -v
```

Expected: `ModuleNotFoundError: No module named 'controlgate.gates.api_gate'`

### Step 3: Implement `api_gate.py`

Create `src/controlgate/gates/api_gate.py`:

```python
"""Gate 10 — API Security Gate.

Detects insecure API patterns: TLS verification disabled, wildcard CORS,
API credentials in query params, and GraphQL introspection in production.

NIST Controls: SC-8, AC-3, SC-5, SI-10
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""verify\s*=\s*False"""),
        "TLS certificate verification disabled — subject to MITM attacks",
        "SC-8",
        "Remove verify=False and use a proper CA bundle; never disable TLS verification in production",
    ),
    (
        re.compile(r"""(?i)(?:CORS_ORIGIN_ALLOW_ALL|allow_all_origins)\s*=\s*True"""),
        "CORS wildcard origin configured — allows any domain to make credentialed requests",
        "AC-3",
        "Restrict CORS to an explicit allowlist of trusted origins",
    ),
    (
        re.compile(r"""Access-Control-Allow-Origin["\s]*[:=]["\s]*\*"""),
        "Access-Control-Allow-Origin: * permits requests from any origin",
        "AC-3",
        "Restrict Access-Control-Allow-Origin to specific trusted origins",
    ),
    (
        re.compile(r"""Access-Control-Allow-Credentials["\s]*[:=]["\s]*["\']?true""", re.IGNORECASE),
        "Access-Control-Allow-Credentials: true with wildcard origin creates CSRF/CORS bypass risk",
        "AC-3",
        "Never combine Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *",
    ),
    (
        re.compile(r"""[?&](?:api[_-]?key|token|access[_-]?token|secret)[=]"""),
        "API key or token passed in URL query parameter — logged in server access logs",
        "SC-8",
        "Pass API credentials in Authorization header, not in URL query parameters",
    ),
    (
        re.compile(r"""(?i)GRAPHQL_INTROSPECTION\s*=\s*True|graphiql\s*=\s*True"""),
        "GraphQL introspection or GraphiQL enabled — exposes full schema to attackers",
        "AC-3",
        "Disable introspection and GraphiQL in non-development environments",
    ),
]


class APIGate(BaseGate):
    """Gate 10: Detect insecure API patterns."""

    name = "API Security Gate"
    gate_id = "api"
    mapped_control_ids = ["SC-8", "AC-3", "SC-5", "SI-10"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                for pattern, description, control_id, remediation in _PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            self._make_finding(
                                control_id=control_id,
                                file=diff_file.path,
                                line=line_no,
                                description=description,
                                evidence=line.strip()[:120],
                                remediation=remediation,
                            )
                        )
        return findings
```

### Step 4: Wire into catalog and __init__

In `src/controlgate/catalog.py` add to `GATE_CONTROL_MAP`:
```python
    "api":           ["SC-8", "AC-3", "SC-5", "SI-10"],
```

In `src/controlgate/gates/__init__.py` add `APIGate` import, to `ALL_GATES`, and `__all__`.

### Step 5: Run tests

```bash
pytest tests/test_gates/test_api_gate.py -v
```

Expected: All PASS.

### Step 6: Commit

```bash
git add src/controlgate/gates/api_gate.py tests/test_gates/test_api_gate.py \
        src/controlgate/catalog.py src/controlgate/gates/__init__.py
git commit -m "feat: add Gate 10 — API Security gate (api, SC-8/AC-3/SC-5)"
```

---

## Task 3: Data Privacy Gate (`privacy`)

**Files:**
- Create: `src/controlgate/gates/privacy_gate.py`
- Create: `tests/test_gates/test_privacy_gate.py`
- Modify: `src/controlgate/catalog.py`
- Modify: `src/controlgate/gates/__init__.py`

### Step 1: Write the failing test

Create `tests/test_gates/test_privacy_gate.py`:

```python
"""Tests for the Data Privacy Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.privacy_gate import PrivacyGate


@pytest.fixture
def gate(catalog):
    return PrivacyGate(catalog)


_PII_IN_LOG_DIFF = """\
diff --git a/views.py b/views.py
--- a/views.py
+++ b/views.py
@@ -1,4 +1,5 @@
 def register(request):
+    logging.debug("User SSN: %s, DOB: %s", user.ssn, user.date_of_birth)
     save(user)
"""

_SERIALIZE_ALL_DIFF = """\
diff --git a/serializers.py b/serializers.py
--- /dev/null
+++ b/serializers.py
@@ -0,0 +1,3 @@
+class UserSerializer(ModelSerializer):
+    serialize_all_fields = True
+    model = User
"""

_NO_EXPIRY_DIFF = """\
diff --git a/models.py b/models.py
--- /dev/null
+++ b/models.py
@@ -0,0 +1,3 @@
+class Session(Model):
+    token = CharField()
+    expires_at = None
"""

_CLEAN_DIFF = """\
diff --git a/views.py b/views.py
--- /dev/null
+++ b/views.py
@@ -0,0 +1,3 @@
+def register(request):
+    logging.info("User registered: user_id=%s", user.id)
+    save(user)
"""


class TestPrivacyGate:
    def test_detects_pii_in_log(self, gate):
        diff_files = parse_diff(_PII_IN_LOG_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("pii" in f.description.lower() or "log" in f.description.lower() for f in findings)

    def test_detects_serialize_all_fields(self, gate):
        diff_files = parse_diff(_SERIALIZE_ALL_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_no_expiry(self, gate):
        diff_files = parse_diff(_NO_EXPIRY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_clean_code_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_PII_IN_LOG_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "privacy"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_PII_IN_LOG_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"PT-2", "PT-3", "SC-28"}
        for f in findings:
            assert f.control_id in valid_ids
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_gates/test_privacy_gate.py -v
```

### Step 3: Implement `privacy_gate.py`

Create `src/controlgate/gates/privacy_gate.py`:

```python
"""Gate 11 — Data Privacy Gate.

Detects PII handling violations: PII in logs, data over-exposure in serializers,
and missing data retention policies.

NIST Controls: PT-2, PT-3, SC-28
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

# PII field name keywords
_PII_FIELDS = r"""(?:ssn|social.?security|date.?of.?birth|dob|credit.?card|card.?number|cvv|passport|drivers.?license)"""

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(
            r"""(?i)(?:logging\.|logger\.|print\().*""" + _PII_FIELDS,
        ),
        "PII field name detected in logging/print statement",
        "PT-3",
        "Remove PII from logs; use opaque identifiers (user_id) instead of PII field values",
    ),
    (
        re.compile(r"""(?i)serialize_all_fields\s*=\s*True"""),
        "serialize_all_fields=True exposes all model fields — may leak PII or sensitive data",
        "PT-2",
        "Use an explicit fields allowlist in serializers; never serialize all fields by default",
    ),
    (
        re.compile(r"""(?i)expires_at\s*=\s*None|ttl\s*[:=]\s*0|ttl\s*[:=]\s*null"""),
        "Data retention field set to null/0 — no expiry policy enforced",
        "SC-28",
        "Set an explicit expires_at or TTL for all data with retention requirements",
    ),
    (
        re.compile(
            r"""(?i)(?:CharField|TextField|StringField|Column\(String)\s*\(.*?""" + _PII_FIELDS,
        ),
        "PII field stored in plaintext database column without encryption marker",
        "SC-28",
        "Encrypt PII at rest using field-level encryption or a dedicated vault",
    ),
]


class PrivacyGate(BaseGate):
    """Gate 11: Detect data privacy and PII handling violations."""

    name = "Data Privacy Gate"
    gate_id = "privacy"
    mapped_control_ids = ["PT-2", "PT-3", "SC-28"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                for pattern, description, control_id, remediation in _PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            self._make_finding(
                                control_id=control_id,
                                file=diff_file.path,
                                line=line_no,
                                description=description,
                                evidence=line.strip()[:120],
                                remediation=remediation,
                            )
                        )
        return findings
```

### Step 4: Wire into catalog and __init__

Add `"privacy": ["PT-2", "PT-3", "SC-28"]` to `GATE_CONTROL_MAP`.
Add `PrivacyGate` to imports, `ALL_GATES`, and `__all__`.

### Step 5: Run and commit

```bash
pytest tests/test_gates/test_privacy_gate.py -v
git add src/controlgate/gates/privacy_gate.py tests/test_gates/test_privacy_gate.py \
        src/controlgate/catalog.py src/controlgate/gates/__init__.py
git commit -m "feat: add Gate 11 — Data Privacy gate (privacy, PT-2/PT-3/SC-28)"
```

---

## Task 4: Resilience & Backup Gate (`resilience`)

**Files:**
- Create: `src/controlgate/gates/resilience_gate.py`
- Create: `tests/test_gates/test_resilience_gate.py`
- Modify: `src/controlgate/catalog.py`
- Modify: `src/controlgate/gates/__init__.py`

### Step 1: Write the failing test

Create `tests/test_gates/test_resilience_gate.py`:

```python
"""Tests for the Resilience & Backup Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.resilience_gate import ResilienceGate


@pytest.fixture
def gate(catalog):
    return ResilienceGate(catalog)


_DELETION_PROTECTION_DIFF = """\
diff --git a/main.tf b/main.tf
--- /dev/null
+++ b/main.tf
@@ -0,0 +1,5 @@
+resource "aws_db_instance" "main" {
+  identifier        = "prod-db"
+  deletion_protection = false
+  instance_class    = "db.t3.micro"
+}
"""

_SKIP_SNAPSHOT_DIFF = """\
diff --git a/database.tf b/database.tf
--- /dev/null
+++ b/database.tf
@@ -0,0 +1,4 @@
+resource "aws_db_instance" "prod" {
+  skip_final_snapshot = true
+  deletion_protection = false
+}
"""

_MAX_RETRIES_ZERO_DIFF = """\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,2 @@
+MAX_RETRIES = 0
+RETRY_DELAY = 1
"""

_CLEAN_DIFF = """\
diff --git a/main.tf b/main.tf
--- /dev/null
+++ b/main.tf
@@ -0,0 +1,5 @@
+resource "aws_db_instance" "main" {
+  identifier          = "prod-db"
+  deletion_protection = true
+  skip_final_snapshot = false
+}
"""


class TestResilienceGate:
    def test_detects_deletion_protection_false(self, gate):
        diff_files = parse_diff(_DELETION_PROTECTION_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("deletion_protection" in f.description.lower() or "backup" in f.description.lower() for f in findings)

    def test_detects_skip_final_snapshot(self, gate):
        diff_files = parse_diff(_SKIP_SNAPSHOT_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_max_retries_zero(self, gate):
        diff_files = parse_diff(_MAX_RETRIES_ZERO_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_clean_config_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_DELETION_PROTECTION_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "resilience"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_DELETION_PROTECTION_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"CP-9", "CP-10", "SI-13"}
        for f in findings:
            assert f.control_id in valid_ids
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_gates/test_resilience_gate.py -v
```

### Step 3: Implement `resilience_gate.py`

Create `src/controlgate/gates/resilience_gate.py`:

```python
"""Gate 12 — Resilience & Backup Gate.

Detects code patterns that disable recoverability: deletion protection off,
no final snapshots, zero retries, and missing connection timeouts.

NIST Controls: CP-9, CP-10, SI-13
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""(?i)deletion.?protection\s*[:=]\s*false"""),
        "deletion_protection disabled — database can be accidentally or maliciously deleted",
        "CP-9",
        "Set deletion_protection = true on all production databases",
    ),
    (
        re.compile(r"""(?i)backup\s*[:=]\s*false"""),
        "Automated backups disabled for database resource",
        "CP-9",
        "Enable automated backups; set backup_retention_period to at least 7 days",
    ),
    (
        re.compile(r"""(?i)skip.?final.?snapshot\s*[:=]\s*true"""),
        "skip_final_snapshot = true — no snapshot taken before database deletion",
        "CP-9",
        "Set skip_final_snapshot = false and specify a final_snapshot_identifier",
    ),
    (
        re.compile(r"""(?i)max.?retries\s*[:=]\s*0"""),
        "max_retries set to 0 — no retry on transient failures",
        "SI-13",
        "Set max_retries to at least 3 with exponential backoff for external service calls",
    ),
    (
        re.compile(r"""(?i)backup.?retention.?period\s*[:=]\s*0"""),
        "backup_retention_period = 0 disables automated database backups",
        "CP-9",
        "Set backup_retention_period to at least 7 days for production databases",
    ),
]


class ResilienceGate(BaseGate):
    """Gate 12: Detect resilience and backup configuration violations."""

    name = "Resilience & Backup Gate"
    gate_id = "resilience"
    mapped_control_ids = ["CP-9", "CP-10", "SI-13"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                for pattern, description, control_id, remediation in _PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            self._make_finding(
                                control_id=control_id,
                                file=diff_file.path,
                                line=line_no,
                                description=description,
                                evidence=line.strip()[:120],
                                remediation=remediation,
                            )
                        )
        return findings
```

### Step 4: Wire and commit

Add `"resilience": ["CP-9", "CP-10", "SI-13"]` to `GATE_CONTROL_MAP`.
Add `ResilienceGate` to `ALL_GATES` and `__all__`.

```bash
pytest tests/test_gates/test_resilience_gate.py -v
git add src/controlgate/gates/resilience_gate.py tests/test_gates/test_resilience_gate.py \
        src/controlgate/catalog.py src/controlgate/gates/__init__.py
git commit -m "feat: add Gate 12 — Resilience & Backup gate (resilience, CP-9/CP-10/SI-13)"
```

---

## Task 5: Incident Response Gate (`incident`)

**Files:**
- Create: `src/controlgate/gates/incident_gate.py`
- Create: `tests/test_gates/test_incident_gate.py`
- Modify: `src/controlgate/catalog.py`
- Modify: `src/controlgate/gates/__init__.py`

### Step 1: Write the failing test

Create `tests/test_gates/test_incident_gate.py`:

```python
"""Tests for the Incident Response Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.incident_gate import IncidentGate


@pytest.fixture
def gate(catalog):
    return IncidentGate(catalog)


_SILENT_EXCEPT_DIFF = """\
diff --git a/worker.py b/worker.py
--- a/worker.py
+++ b/worker.py
@@ -1,4 +1,6 @@
 def process():
+    try:
+        do_work()
+    except:
+        pass
"""

_EMPTY_CATCH_JS_DIFF = """\
diff --git a/handler.js b/handler.js
--- /dev/null
+++ b/handler.js
@@ -0,0 +1,5 @@
+async function handle() {
+  try {
+    await process();
+  } catch(e) {}
+}
"""

_TRACEBACK_DIFF = """\
diff --git a/app.py b/app.py
--- /dev/null
+++ b/app.py
@@ -0,0 +1,4 @@
+@app.errorhandler(500)
+def server_error(e):
+    traceback.print_exc()
+    return str(e), 500
"""

_NOTIFY_FALSE_DIFF = """\
diff --git a/alerting.yaml b/alerting.yaml
--- /dev/null
+++ b/alerting.yaml
@@ -0,0 +1,3 @@
+alerts:
+  notify: false
+  threshold: critical
"""

_CLEAN_DIFF = """\
diff --git a/worker.py b/worker.py
--- /dev/null
+++ b/worker.py
@@ -0,0 +1,6 @@
+def process():
+    try:
+        do_work()
+    except ValueError as e:
+        logger.error("Processing failed: %s", e)
+        raise
"""


class TestIncidentGate:
    def test_detects_bare_except_pass(self, gate):
        diff_files = parse_diff(_SILENT_EXCEPT_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("exception" in f.description.lower() or "silent" in f.description.lower() for f in findings)

    def test_detects_empty_catch_js(self, gate):
        diff_files = parse_diff(_EMPTY_CATCH_JS_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_traceback_exposure(self, gate):
        diff_files = parse_diff(_TRACEBACK_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_notify_false(self, gate):
        diff_files = parse_diff(_NOTIFY_FALSE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_logged_exception_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_SILENT_EXCEPT_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "incident"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_SILENT_EXCEPT_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"IR-4", "IR-6", "AU-6"}
        for f in findings:
            assert f.control_id in valid_ids
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_gates/test_incident_gate.py -v
```

### Step 3: Implement `incident_gate.py`

Create `src/controlgate/gates/incident_gate.py`:

```python
"""Gate 13 — Incident Response Gate.

Ensures code changes don't remove alerting, monitoring, or incident-handling
capability: silent exception swallowing, stack trace exposure, disabled notifications.

NIST Controls: IR-4, IR-6, AU-6
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""^\s*except\s*:\s*$""", re.MULTILINE),
        "Bare except clause silently swallows all exceptions — prevents incident detection",
        "IR-4",
        "Catch specific exceptions and log them; never use bare except: pass",
    ),
    (
        re.compile(r"""^\s*except.*:\s*\n\s*pass\s*$""", re.MULTILINE),
        "Exception handler with only 'pass' — incident will be silently ignored",
        "IR-4",
        "Log the exception before passing; use logger.exception() to capture stack trace",
    ),
    (
        re.compile(r"""catch\s*\([^)]*\)\s*\{\s*\}"""),
        "Empty catch block — exception swallowed silently in JS/TS/Java",
        "IR-4",
        "Log or rethrow exceptions; never leave catch blocks empty",
    ),
    (
        re.compile(r"""traceback\.print_exc\(\)|traceback\.format_exc\(\)"""),
        "Stack trace exposed in response — leaks implementation details to attackers",
        "IR-4",
        "Log the traceback server-side only; return a generic error message to clients",
    ),
    (
        re.compile(r"""(?i)notify\s*[:=]\s*false|notifications.?enabled\s*[:=]\s*false"""),
        "Alerting/notification disabled in monitoring configuration",
        "IR-6",
        "Enable notifications for all critical alerts; silence specific alerts rather than disabling all",
    ),
]


class IncidentGate(BaseGate):
    """Gate 13: Detect incident response capability removal."""

    name = "Incident Response Gate"
    gate_id = "incident"
    mapped_control_ids = ["IR-4", "IR-6", "AU-6"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            # For multi-line patterns, scan the full added content
            full_content = diff_file.full_content
            for pattern, description, control_id, remediation in _PATTERNS:
                if pattern.flags & re.MULTILINE:
                    if pattern.search(full_content):
                        findings.append(
                            self._make_finding(
                                control_id=control_id,
                                file=diff_file.path,
                                line=1,
                                description=description,
                                evidence=full_content[:120],
                                remediation=remediation,
                            )
                        )
                else:
                    for line_no, line in diff_file.all_added_lines:
                        if pattern.search(line):
                            findings.append(
                                self._make_finding(
                                    control_id=control_id,
                                    file=diff_file.path,
                                    line=line_no,
                                    description=description,
                                    evidence=line.strip()[:120],
                                    remediation=remediation,
                                )
                            )
        return findings
```

### Step 4: Wire and commit

Add `"incident": ["IR-4", "IR-6", "AU-6"]` to `GATE_CONTROL_MAP`.
Add `IncidentGate` to `ALL_GATES` and `__all__`.

```bash
pytest tests/test_gates/test_incident_gate.py -v
git add src/controlgate/gates/incident_gate.py tests/test_gates/test_incident_gate.py \
        src/controlgate/catalog.py src/controlgate/gates/__init__.py
git commit -m "feat: add Gate 13 — Incident Response gate (incident, IR-4/IR-6/AU-6)"
```

---

## Task 6: Observability Gate (`observability`)

**Files:**
- Create: `src/controlgate/gates/observability_gate.py`
- Create: `tests/test_gates/test_observability_gate.py`
- Modify: `src/controlgate/catalog.py`
- Modify: `src/controlgate/gates/__init__.py`

### Step 1: Write the failing test

Create `tests/test_gates/test_observability_gate.py`:

```python
"""Tests for the Observability Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.observability_gate import ObservabilityGate


@pytest.fixture
def gate(catalog):
    return ObservabilityGate(catalog)


_MONITORING_FALSE_DIFF = """\
diff --git a/main.tf b/main.tf
--- /dev/null
+++ b/main.tf
@@ -0,0 +1,4 @@
+resource "aws_db_instance" "prod" {
+  monitoring_interval = 0
+  enable_monitoring   = false
+}
"""

_LOG_DRIVER_NONE_DIFF = """\
diff --git a/docker-compose.yml b/docker-compose.yml
--- /dev/null
+++ b/docker-compose.yml
@@ -0,0 +1,5 @@
+services:
+  app:
+    image: myapp:1.0
+    logging:
+      driver: none
"""

_K8S_NO_PROBE_DIFF = """\
diff --git a/deployment.yaml b/deployment.yaml
--- /dev/null
+++ b/deployment.yaml
@@ -0,0 +1,8 @@
+apiVersion: apps/v1
+kind: Deployment
+spec:
+  template:
+    spec:
+      containers:
+      - name: app
+        image: myapp:1.0
"""

_CLEAN_DIFF = """\
diff --git a/deployment.yaml b/deployment.yaml
--- /dev/null
+++ b/deployment.yaml
@@ -0,0 +1,10 @@
+apiVersion: apps/v1
+kind: Deployment
+spec:
+  template:
+    spec:
+      containers:
+      - name: app
+        image: myapp:1.0
+        livenessProbe:
+          httpGet: {path: /health, port: 8080}
"""


class TestObservabilityGate:
    def test_detects_monitoring_false(self, gate):
        diff_files = parse_diff(_MONITORING_FALSE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("monitor" in f.description.lower() for f in findings)

    def test_detects_log_driver_none(self, gate):
        diff_files = parse_diff(_LOG_DRIVER_NONE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_k8s_missing_liveness_probe(self, gate):
        diff_files = parse_diff(_K8S_NO_PROBE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_k8s_with_liveness_probe_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_MONITORING_FALSE_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "observability"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_MONITORING_FALSE_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"SI-4", "AU-12"}
        for f in findings:
            assert f.control_id in valid_ids
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_gates/test_observability_gate.py -v
```

### Step 3: Implement `observability_gate.py`

Create `src/controlgate/gates/observability_gate.py`:

```python
"""Gate 14 — Observability Gate.

Detects removal of metrics, health probes, and monitoring configuration —
distinct from the Audit gate which focuses on log content.

NIST Controls: SI-4, AU-12
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""(?i)enable.?monitoring\s*[:=]\s*false|monitoring\s*[:=]\s*false"""),
        "Monitoring disabled in infrastructure configuration",
        "SI-4",
        "Enable monitoring and set monitoring_interval > 0 for all production resources",
    ),
    (
        re.compile(r"""(?i)monitoring.?interval\s*[:=]\s*0"""),
        "monitoring_interval = 0 disables enhanced monitoring",
        "SI-4",
        "Set monitoring_interval to 60 or higher for production database instances",
    ),
    (
        re.compile(r"""(?i)logging:\s*\n\s*driver:\s*none|log.?driver\s*[:=]\s*["\']?none"""),
        "Container logging driver set to 'none' — all output is discarded",
        "AU-12",
        "Use a persistent logging driver (json-file, awslogs, fluentd) for all containers",
    ),
    (
        re.compile(r"""--log-driver=none"""),
        "Container logging disabled via CLI flag",
        "AU-12",
        "Remove --log-driver=none; all container output must be captured for audit",
    ),
]

# Kubernetes deployment file pattern — needs separate handling
_K8S_FILE_PATTERN = re.compile(r"""(?i)(?:deployment|statefulset|daemonset).*\.ya?ml$""")
_LIVENESS_PROBE_PATTERN = re.compile(r"""livenessProbe""")


class ObservabilityGate(BaseGate):
    """Gate 14: Detect removal of monitoring, health probes, and observability."""

    name = "Observability Gate"
    gate_id = "observability"
    mapped_control_ids = ["SI-4", "AU-12"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            # Line-level pattern scan
            for line_no, line in diff_file.all_added_lines:
                for pattern, description, control_id, remediation in _PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            self._make_finding(
                                control_id=control_id,
                                file=diff_file.path,
                                line=line_no,
                                description=description,
                                evidence=line.strip()[:120],
                                remediation=remediation,
                            )
                        )

            # Kubernetes workload: flag if new containers added without liveness probe
            if diff_file.is_new and _K8S_FILE_PATTERN.search(diff_file.path):
                full_content = diff_file.full_content
                if "containers:" in full_content and not _LIVENESS_PROBE_PATTERN.search(full_content):
                    findings.append(
                        self._make_finding(
                            control_id="SI-4",
                            file=diff_file.path,
                            line=1,
                            description="Kubernetes workload added without a livenessProbe — failure will not be detected",
                            evidence=f"No livenessProbe found in {diff_file.path}",
                            remediation="Add a livenessProbe (httpGet, tcpSocket, or exec) to all container specs",
                        )
                    )

        return findings
```

### Step 4: Wire and commit

Add `"observability": ["SI-4", "AU-12"]` to `GATE_CONTROL_MAP`.
Add `ObservabilityGate` to `ALL_GATES` and `__all__`.

```bash
pytest tests/test_gates/test_observability_gate.py -v
git add src/controlgate/gates/observability_gate.py tests/test_gates/test_observability_gate.py \
        src/controlgate/catalog.py src/controlgate/gates/__init__.py
git commit -m "feat: add Gate 14 — Observability gate (observability, SI-4/AU-12)"
```

---

## Task 7: Memory Safety Gate (`memsafe`)

**Files:**
- Create: `src/controlgate/gates/memsafe_gate.py`
- Create: `tests/test_gates/test_memsafe_gate.py`
- Modify: `src/controlgate/catalog.py`
- Modify: `src/controlgate/gates/__init__.py`

### Step 1: Write the failing test

Create `tests/test_gates/test_memsafe_gate.py`:

```python
"""Tests for the Memory Safety Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.memsafe_gate import MemSafeGate


@pytest.fixture
def gate(catalog):
    return MemSafeGate(catalog)


_EVAL_DYNAMIC_DIFF = """\
diff --git a/app.py b/app.py
--- /dev/null
+++ b/app.py
@@ -0,0 +1,3 @@
+def process(user_input):
+    result = eval(user_input)
+    return result
"""

_EXEC_DYNAMIC_DIFF = """\
diff --git a/template.py b/template.py
--- /dev/null
+++ b/template.py
@@ -0,0 +1,2 @@
+code = f"x = {request.form['value']}"
+exec(code)
"""

_UNSAFE_RUST_DIFF = """\
diff --git a/src/lib.rs b/src/lib.rs
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,5 @@
+pub fn read_ptr(ptr: *const u8) -> u8 {
+    unsafe {
+        *ptr
+    }
+}
"""

_STRCPY_DIFF = """\
diff --git a/handler.c b/handler.c
--- /dev/null
+++ b/handler.c
@@ -0,0 +1,4 @@
+void copy_name(char *dest, char *src) {
+    strcpy(dest, src);
+}
"""

_CLEAN_DIFF = """\
diff --git a/app.py b/app.py
--- /dev/null
+++ b/app.py
@@ -0,0 +1,3 @@
+import ast
+def process(user_input):
+    return ast.literal_eval(user_input)
"""


class TestMemSafeGate:
    def test_detects_eval_dynamic(self, gate):
        diff_files = parse_diff(_EVAL_DYNAMIC_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("eval" in f.description.lower() for f in findings)

    def test_detects_exec_dynamic(self, gate):
        diff_files = parse_diff(_EXEC_DYNAMIC_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_unsafe_rust(self, gate):
        diff_files = parse_diff(_UNSAFE_RUST_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_strcpy(self, gate):
        diff_files = parse_diff(_STRCPY_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_ast_literal_eval_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_EVAL_DYNAMIC_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "memsafe"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_EVAL_DYNAMIC_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"SI-16", "CM-7"}
        for f in findings:
            assert f.control_id in valid_ids
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_gates/test_memsafe_gate.py -v
```

### Step 3: Implement `memsafe_gate.py`

Create `src/controlgate/gates/memsafe_gate.py`:

```python
"""Gate 15 — Memory Safety Gate.

Detects dynamic code execution, unsafe memory operations, and patterns
that historically lead to memory corruption and code injection.

NIST Controls: SI-16, CM-7
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""(?<!\w)eval\s*\((?!\s*["\'])"""),
        "eval() called with dynamic argument — arbitrary code execution risk",
        "SI-16",
        "Use ast.literal_eval() for data; never eval() user-controlled input",
    ),
    (
        re.compile(r"""(?<!\w)exec\s*\("""),
        "exec() detected — executes arbitrary Python code at runtime",
        "SI-16",
        "Avoid exec(); use explicit function dispatch or importlib for dynamic behavior",
    ),
    (
        re.compile(r"""unsafe\s*\{"""),
        "Unsafe Rust block — must have an explicit safety justification comment",
        "CM-7",
        "Add a // SAFETY: comment explaining the invariants that make this block safe",
    ),
    (
        re.compile(r"""ctypes\.\w+.*\baddress\b|ctypes\.cast|ctypes\.memmove|ctypes\.memset"""),
        "ctypes raw memory operation — bypasses Python memory safety",
        "SI-16",
        "Audit ctypes usage; prefer cffi with stricter type checking or avoid direct memory access",
    ),
    (
        re.compile(r"""\bstrcpy\s*\(|\bstrcat\s*\("""),
        "strcpy/strcat used without bounds checking — classic buffer overflow vector",
        "SI-16",
        "Use strlcpy/strlcat or snprintf with explicit size limits",
    ),
    (
        re.compile(r"""\bmemcpy\s*\(.*req|input|user|argv"""),
        "memcpy with potentially untrusted source length — buffer overflow risk",
        "SI-16",
        "Validate source buffer size before memcpy; consider memmove for overlapping regions",
    ),
]


class MemSafeGate(BaseGate):
    """Gate 15: Detect memory safety and dynamic code execution violations."""

    name = "Memory Safety Gate"
    gate_id = "memsafe"
    mapped_control_ids = ["SI-16", "CM-7"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                for pattern, description, control_id, remediation in _PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            self._make_finding(
                                control_id=control_id,
                                file=diff_file.path,
                                line=line_no,
                                description=description,
                                evidence=line.strip()[:120],
                                remediation=remediation,
                            )
                        )
        return findings
```

### Step 4: Wire and commit

Add `"memsafe": ["SI-16", "CM-7"]` to `GATE_CONTROL_MAP`.
Add `MemSafeGate` to `ALL_GATES` and `__all__`.

```bash
pytest tests/test_gates/test_memsafe_gate.py -v
git add src/controlgate/gates/memsafe_gate.py tests/test_gates/test_memsafe_gate.py \
        src/controlgate/catalog.py src/controlgate/gates/__init__.py
git commit -m "feat: add Gate 15 — Memory Safety gate (memsafe, SI-16/CM-7)"
```

---

## Task 8: License Compliance Gate (`license`)

**Files:**
- Create: `src/controlgate/gates/license_gate.py`
- Create: `tests/test_gates/test_license_gate.py`
- Modify: `src/controlgate/catalog.py`
- Modify: `src/controlgate/gates/__init__.py`

### Step 1: Write the failing test

Create `tests/test_gates/test_license_gate.py`:

```python
"""Tests for the License Compliance Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.license_gate import LicenseGate


@pytest.fixture
def gate(catalog):
    return LicenseGate(catalog)


_GPL_PIP_DIFF = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 requests==2.31.0
+gpl-licensed-lib==1.0.0  # GPL-3.0
"""

_AGPL_PACKAGE_JSON_DIFF = """\
diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -1,5 +1,8 @@
 {
   "dependencies": {
+    "some-agpl-package": "^1.0.0"
   }
 }
"""

_SPDX_GPL_DIFF = """\
diff --git a/src/vendor/lib.py b/src/vendor/lib.py
--- /dev/null
+++ b/src/vendor/lib.py
@@ -0,0 +1,2 @@
+# SPDX-License-Identifier: GPL-3.0-only
+def helper(): pass
"""

_MIT_CLEAN_DIFF = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
 requests==2.31.0
+flask==3.0.0  # MIT
"""


class TestLicenseGate:
    def test_detects_gpl_in_requirements(self, gate):
        diff_files = parse_diff(_GPL_PIP_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("gpl" in f.description.lower() or "license" in f.description.lower() for f in findings)

    def test_detects_agpl_in_package_json(self, gate):
        diff_files = parse_diff(_AGPL_PACKAGE_JSON_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_spdx_gpl_in_source(self, gate):
        diff_files = parse_diff(_SPDX_GPL_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_mit_license_no_findings(self, gate):
        diff_files = parse_diff(_MIT_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_GPL_PIP_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "license"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_GPL_PIP_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"SA-4", "SR-3"}
        for f in findings:
            assert f.control_id in valid_ids
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_gates/test_license_gate.py -v
```

### Step 3: Implement `license_gate.py`

Create `src/controlgate/gates/license_gate.py`:

```python
"""Gate 16 — License Compliance Gate.

Prevents copyleft-licensed dependencies from entering proprietary codebases.
Detects GPL, AGPL, SSPL, and LGPL licenses in dependency manifests and source files.

NIST Controls: SA-4, SR-3
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

# Copyleft license keywords in comments or SPDX identifiers
_COPYLEFT_PATTERN = re.compile(
    r"""(?i)\b(?:GPL|AGPL|SSPL|LGPL|GNU\s+(?:General|Affero|Lesser))\b"""
)

# Package manifest files to scan
_MANIFEST_FILES = re.compile(
    r"""(?i)(?:requirements.*\.txt|package\.json|go\.mod|Cargo\.toml|Gemfile|composer\.json|setup\.cfg|pyproject\.toml)$"""
)

# SPDX copyleft identifiers
_SPDX_COPYLEFT = re.compile(
    r"""SPDX-License-Identifier:\s*(?:GPL|AGPL|SSPL|LGPL|EUPL|OSL|CDDL)"""
)

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        _COPYLEFT_PATTERN,
        "Copyleft license (GPL/AGPL/SSPL/LGPL) detected in dependency manifest",
        "SA-4",
        "Review license compatibility; copyleft licenses may require open-sourcing your codebase",
    ),
    (
        _SPDX_COPYLEFT,
        "SPDX copyleft license identifier in source file",
        "SR-3",
        "Audit this file's license; copyleft source may contaminate your proprietary codebase",
    ),
]


class LicenseGate(BaseGate):
    """Gate 16: Detect copyleft license compliance violations."""

    name = "License Compliance Gate"
    gate_id = "license"
    mapped_control_ids = ["SA-4", "SR-3"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            is_manifest = bool(_MANIFEST_FILES.search(diff_file.path))
            for line_no, line in diff_file.all_added_lines:
                # Only flag copyleft keywords in manifest files to reduce false positives
                if is_manifest and _COPYLEFT_PATTERN.search(line):
                    findings.append(
                        self._make_finding(
                            control_id="SA-4",
                            file=diff_file.path,
                            line=line_no,
                            description="Copyleft license (GPL/AGPL/SSPL/LGPL) detected in dependency manifest",
                            evidence=line.strip()[:120],
                            remediation="Review license compatibility; copyleft licenses may require open-sourcing your codebase",
                        )
                    )
                # SPDX identifiers in any source file
                if _SPDX_COPYLEFT.search(line):
                    findings.append(
                        self._make_finding(
                            control_id="SR-3",
                            file=diff_file.path,
                            line=line_no,
                            description="SPDX copyleft license identifier in source file",
                            evidence=line.strip()[:120],
                            remediation="Audit this file's license; copyleft source may contaminate your proprietary codebase",
                        )
                    )
        return findings
```

### Step 4: Wire and commit

Add `"license": ["SA-4", "SR-3"]` to `GATE_CONTROL_MAP`.
Add `LicenseGate` to `ALL_GATES` and `__all__`.

```bash
pytest tests/test_gates/test_license_gate.py -v
git add src/controlgate/gates/license_gate.py tests/test_gates/test_license_gate.py \
        src/controlgate/catalog.py src/controlgate/gates/__init__.py
git commit -m "feat: add Gate 16 — License Compliance gate (license, SA-4/SR-3)"
```

---

## Task 9: AI/ML Security Gate (`aiml`)

**Files:**
- Create: `src/controlgate/gates/aiml_gate.py`
- Create: `tests/test_gates/test_aiml_gate.py`
- Modify: `src/controlgate/catalog.py`
- Modify: `src/controlgate/gates/__init__.py`

### Step 1: Write the failing test

Create `tests/test_gates/test_aiml_gate.py`:

```python
"""Tests for the AI/ML Security Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.aiml_gate import AIMLGate


@pytest.fixture
def gate(catalog):
    return AIMLGate(catalog)


_TRUST_REMOTE_CODE_DIFF = """\
diff --git a/model.py b/model.py
--- /dev/null
+++ b/model.py
@@ -0,0 +1,3 @@
+from transformers import AutoModelForCausalLM
+model = AutoModelForCausalLM.from_pretrained("some/model", trust_remote_code=True)
"""

_PICKLE_LOAD_DIFF = """\
diff --git a/inference.py b/inference.py
--- /dev/null
+++ b/inference.py
@@ -0,0 +1,4 @@
+import pickle
+with open("model.pkl", "rb") as f:
+    model = pickle.load(f)
"""

_HTTP_MODEL_DIFF = """\
diff --git a/download.py b/download.py
--- /dev/null
+++ b/download.py
@@ -0,0 +1,3 @@
+import urllib.request
+urllib.request.urlretrieve("http://models.example.com/weights.bin", "weights.bin")
"""

_PROMPT_INJECTION_DIFF = """\
diff --git a/llm.py b/llm.py
--- /dev/null
+++ b/llm.py
@@ -0,0 +1,4 @@
+def query_llm(user_input):
+    prompt = f"Answer this: {user_input}"
+    return llm.complete(prompt)
"""

_CLEAN_DIFF = """\
diff --git a/model.py b/model.py
--- /dev/null
+++ b/model.py
@@ -0,0 +1,4 @@
+import torch
+model = torch.load("model.pt", map_location="cpu")
+model.eval()
"""


class TestAIMLGate:
    def test_detects_trust_remote_code(self, gate):
        diff_files = parse_diff(_TRUST_REMOTE_CODE_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("trust_remote_code" in f.description.lower() or "remote" in f.description.lower() for f in findings)

    def test_detects_pickle_load(self, gate):
        diff_files = parse_diff(_PICKLE_LOAD_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_http_model_download(self, gate):
        diff_files = parse_diff(_HTTP_MODEL_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_prompt_injection_pattern(self, gate):
        diff_files = parse_diff(_PROMPT_INJECTION_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_clean_model_load_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_TRUST_REMOTE_CODE_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "aiml"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_TRUST_REMOTE_CODE_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"SI-10", "SC-28", "SR-3"}
        for f in findings:
            assert f.control_id in valid_ids
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_gates/test_aiml_gate.py -v
```

### Step 3: Implement `aiml_gate.py`

Create `src/controlgate/gates/aiml_gate.py`:

```python
"""Gate 17 — AI/ML Security Gate.

Detects security risks specific to AI/ML codebases: prompt injection vectors,
unsafe model loading, remote code execution via trust_remote_code, and
insecure model transfer channels.

NIST Controls: SI-10, SC-28, SR-3
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""trust_remote_code\s*=\s*True"""),
        "trust_remote_code=True executes arbitrary code from a remote model repository",
        "SR-3",
        "Never use trust_remote_code=True; audit the model source and load from a vetted internal registry",
    ),
    (
        re.compile(r"""pickle\.load\s*\(|pickle\.loads\s*\("""),
        "pickle.load() deserializes arbitrary Python objects — code execution on load",
        "SI-10",
        "Use safetensors or ONNX format instead of pickle; never load pickle files from untrusted sources",
    ),
    (
        re.compile(r"""joblib\.load\s*\("""),
        "joblib.load() uses pickle internally — arbitrary code execution risk",
        "SI-10",
        "Verify the source and checksum of joblib files before loading; prefer safetensors",
    ),
    (
        re.compile(r"""http://[^\s]*(?:model|weight|checkpoint|\.bin|\.pt|\.pkl|\.onnx)"""),
        "Model or weights downloaded over unencrypted HTTP",
        "SR-3",
        "Use HTTPS for all model downloads and verify checksums (SHA256) after download",
    ),
    (
        re.compile(r"""f["\'].*\{.*(?:user|request|input|query|prompt).*\}.*["\']"""),
        "User input interpolated directly into LLM prompt — prompt injection risk",
        "SI-10",
        "Sanitize and validate user input before including in prompts; use structured message formats",
    ),
]


class AIMLGate(BaseGate):
    """Gate 17: Detect AI/ML-specific security vulnerabilities."""

    name = "AI/ML Security Gate"
    gate_id = "aiml"
    mapped_control_ids = ["SI-10", "SC-28", "SR-3"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                for pattern, description, control_id, remediation in _PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            self._make_finding(
                                control_id=control_id,
                                file=diff_file.path,
                                line=line_no,
                                description=description,
                                evidence=line.strip()[:120],
                                remediation=remediation,
                            )
                        )
        return findings
```

### Step 4: Wire and commit

Add `"aiml": ["SI-10", "SC-28", "SR-3"]` to `GATE_CONTROL_MAP`.
Add `AIMLGate` to `ALL_GATES` and `__all__`.

```bash
pytest tests/test_gates/test_aiml_gate.py -v
git add src/controlgate/gates/aiml_gate.py tests/test_gates/test_aiml_gate.py \
        src/controlgate/catalog.py src/controlgate/gates/__init__.py
git commit -m "feat: add Gate 17 — AI/ML Security gate (aiml, SI-10/SC-28/SR-3)"
```

---

## Task 10: Container Security Gate (`container`)

**Files:**
- Create: `src/controlgate/gates/container_gate.py`
- Create: `tests/test_gates/test_container_gate.py`
- Modify: `src/controlgate/catalog.py`
- Modify: `src/controlgate/gates/__init__.py`

### Step 1: Write the failing test

Create `tests/test_gates/test_container_gate.py`:

```python
"""Tests for the Container Security Gate."""

import pytest

from controlgate.diff_parser import parse_diff
from controlgate.gates.container_gate import ContainerGate


@pytest.fixture
def gate(catalog):
    return ContainerGate(catalog)


_ROOT_USER_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,3 @@
+FROM python:3.11
+USER root
+CMD ["python", "app.py"]
"""

_PRIVILEGED_DIFF = """\
diff --git a/docker-compose.yml b/docker-compose.yml
--- /dev/null
+++ b/docker-compose.yml
@@ -0,0 +1,5 @@
+services:
+  app:
+    image: myapp:1.0
+    privileged: true
"""

_LATEST_TAG_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,2 @@
+FROM nginx:latest
+EXPOSE 80
"""

_HOST_NETWORK_DIFF = """\
diff --git a/deployment.yaml b/deployment.yaml
--- /dev/null
+++ b/deployment.yaml
@@ -0,0 +1,5 @@
+spec:
+  template:
+    spec:
+      hostNetwork: true
+      containers: []
"""

_HOST_PID_DIFF = """\
diff --git a/deployment.yaml b/deployment.yaml
--- /dev/null
+++ b/deployment.yaml
@@ -0,0 +1,4 @@
+spec:
+  template:
+    spec:
+      hostPID: true
"""

_LOG_DRIVER_NONE_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,2 @@
+FROM python:3.11
"""

_CLEAN_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
--- /dev/null
+++ b/Dockerfile
@@ -0,0 +1,5 @@
+FROM python:3.11-slim@sha256:abc123
+RUN groupadd -r app && useradd -r -g app app
+COPY . /app
+USER app
+CMD ["python", "app.py"]
"""


class TestContainerGate:
    def test_detects_user_root(self, gate):
        diff_files = parse_diff(_ROOT_USER_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("root" in f.description.lower() for f in findings)

    def test_detects_privileged_mode(self, gate):
        diff_files = parse_diff(_PRIVILEGED_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_latest_tag(self, gate):
        diff_files = parse_diff(_LATEST_TAG_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0
        assert any("latest" in f.description.lower() or "unpinned" in f.description.lower() for f in findings)

    def test_detects_host_network(self, gate):
        diff_files = parse_diff(_HOST_NETWORK_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_detects_host_pid(self, gate):
        diff_files = parse_diff(_HOST_PID_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) > 0

    def test_clean_dockerfile_no_findings(self, gate):
        diff_files = parse_diff(_CLEAN_DIFF)
        findings = gate.scan(diff_files)
        assert len(findings) == 0

    def test_findings_have_gate_id(self, gate):
        diff_files = parse_diff(_ROOT_USER_DIFF)
        findings = gate.scan(diff_files)
        for f in findings:
            assert f.gate == "container"

    def test_findings_have_valid_control_ids(self, gate):
        diff_files = parse_diff(_ROOT_USER_DIFF)
        findings = gate.scan(diff_files)
        valid_ids = {"CM-6", "CM-7", "SC-7", "SC-39", "AC-6", "SI-7", "AU-12", "SA-10", "SR-3"}
        for f in findings:
            assert f.control_id in valid_ids
```

### Step 2: Run test to verify it fails

```bash
pytest tests/test_gates/test_container_gate.py -v
```

### Step 3: Implement `container_gate.py`

Create `src/controlgate/gates/container_gate.py`:

```python
"""Gate 18 — Container Security Gate.

Detects container and Kubernetes misconfigurations across five security domains:
image integrity, least privilege, network isolation, runtime hardening, and audit.

NIST Controls: CM-6, CM-7, SC-7, SC-39, AC-6, SI-7, AU-12, SA-10, SR-3

Note: Each pattern uses a single primary control ID (most directly relevant).
Secondary controls are noted in remediation text.
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

# ── IMAGE INTEGRITY (primary: SI-7) ──────────────────────────────────────────
_IMAGE_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""FROM\s+\S+:latest"""),
        "Unpinned :latest tag — image may change between builds, breaking reproducibility",
        "SI-7",
        "Pin to a specific version tag or use a digest: FROM python@sha256:<hash>",
    ),
    (
        re.compile(r"""^FROM\s+[^\s@:]+\s*$""", re.MULTILINE),
        "Base image has no tag — always pin to a specific digest or version",
        "SI-7",
        "Add a version tag or SHA256 digest: FROM python:3.11-slim@sha256:<hash>",
    ),
    (
        re.compile(r"""ADD\s+https?://"""),
        "Remote ADD fetches content at build time without checksum verification",
        "SI-7",
        "Use RUN curl ... | sha256sum -c and COPY instead of ADD with remote URLs",
    ),
]

# ── LEAST PRIVILEGE (primary: AC-6) ──────────────────────────────────────────
_PRIVILEGE_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""USER\s+root"""),
        "Container explicitly set to run as root — violates least privilege",
        "AC-6",
        "Create a dedicated non-root user: RUN useradd -r app && USER app",
    ),
    (
        re.compile(r"""(?i)privileged:\s*true|--privileged"""),
        "Privileged container grants full host access — enables container escape",
        "AC-6",
        "Remove privileged: true; grant only specific capabilities if needed",
    ),
    (
        re.compile(r"""--cap-add\s+ALL"""),
        "ALL Linux capabilities granted — equivalent to running as root",
        "AC-6",
        "Enumerate only the specific capabilities required (e.g. --cap-add NET_BIND_SERVICE)",
    ),
    (
        re.compile(r"""--cap-add\s+(?:SYS_ADMIN|SYS_PTRACE|NET_ADMIN)"""),
        "High-risk Linux capability granted — can lead to host privilege escalation",
        "AC-6",
        "Audit whether this capability is truly needed; prefer dropping all caps and adding selectively",
    ),
    (
        re.compile(r"""allowPrivilegeEscalation:\s*true"""),
        "allowPrivilegeEscalation: true permits setuid/setgid escalation inside the container",
        "AC-6",
        "Set allowPrivilegeEscalation: false in securityContext",
    ),
    (
        re.compile(r"""runAsNonRoot:\s*false"""),
        "runAsNonRoot: false explicitly permits the container to run as root",
        "AC-6",
        "Set runAsNonRoot: true and specify runAsUser with a non-zero UID",
    ),
]

# ── NETWORK ISOLATION (primary: SC-7) ────────────────────────────────────────
_NETWORK_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""hostNetwork:\s*true"""),
        "hostNetwork: true exposes the container on the host network namespace",
        "SC-7",
        "Use ClusterIP or NodePort Services; avoid sharing the host network namespace",
    ),
    (
        re.compile(r"""hostPort:\s*\d+"""),
        "hostPort bypasses Kubernetes NetworkPolicy — use Service resources instead",
        "SC-7",
        "Replace hostPort with a Kubernetes Service of type NodePort or LoadBalancer",
    ),
]

# ── RUNTIME HARDENING (primary: SC-39) ───────────────────────────────────────
_RUNTIME_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""readOnlyRootFilesystem:\s*false"""),
        "Writable root filesystem — allows attacker to modify container files",
        "SC-39",
        "Set readOnlyRootFilesystem: true and use emptyDir/PVC mounts for writable paths",
    ),
    (
        re.compile(r"""hostPID:\s*true"""),
        "hostPID: true shares the host process namespace — enables container escape vectors",
        "SC-39",
        "Remove hostPID: true; process isolation must be maintained",
    ),
    (
        re.compile(r"""hostIPC:\s*true"""),
        "hostIPC: true shares host IPC namespace — allows cross-container memory access",
        "SC-39",
        "Remove hostIPC: true; IPC namespace isolation must be maintained",
    ),
    (
        re.compile(r"""seccompProfile.*Unconfined|seccomp.*unconfined""", re.IGNORECASE),
        "Seccomp profile set to Unconfined — all syscalls permitted",
        "SC-39",
        "Use RuntimeDefault seccomp profile or create a custom restricted profile",
    ),
]

# ── AUDIT (primary: AU-12) ────────────────────────────────────────────────────
_AUDIT_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""log.?driver.*none|logging:\s*\n\s*driver:\s*none""", re.IGNORECASE),
        "Container logging driver set to 'none' — all container output is discarded",
        "AU-12",
        "Use a persistent logging driver (json-file, awslogs, fluentd, splunk)",
    ),
    (
        re.compile(r"""--log-driver=none"""),
        "Container logging disabled via CLI flag — cannot audit container activity",
        "AU-12",
        "Remove --log-driver=none; use a centralised logging destination",
    ),
]

# ── RESOURCE LIMITS (primary: CM-6) ──────────────────────────────────────────
_RESOURCE_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""resources:\s*\{\}"""),
        "Empty resources block — no CPU/memory limits set; enables denial-of-service",
        "CM-6",
        "Set explicit resources.requests and resources.limits for CPU and memory",
    ),
    (
        re.compile(r"""--memory[= ]["\']?-1"""),
        "Unlimited container memory allocation — no ceiling for memory consumption",
        "CM-6",
        "Set an explicit --memory limit (e.g. --memory=512m)",
    ),
]

_ALL_PATTERN_GROUPS = [
    _IMAGE_PATTERNS,
    _PRIVILEGE_PATTERNS,
    _NETWORK_PATTERNS,
    _RUNTIME_PATTERNS,
    _AUDIT_PATTERNS,
    _RESOURCE_PATTERNS,
]


class ContainerGate(BaseGate):
    """Gate 18: Detect container and Kubernetes security misconfigurations."""

    name = "Container Security Gate"
    gate_id = "container"
    mapped_control_ids = ["CM-6", "CM-7", "SC-7", "SC-39", "AC-6", "SI-7", "AU-12", "SA-10", "SR-3"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                for pattern_group in _ALL_PATTERN_GROUPS:
                    for pattern, description, control_id, remediation in pattern_group:
                        if pattern.search(line):
                            findings.append(
                                self._make_finding(
                                    control_id=control_id,
                                    file=diff_file.path,
                                    line=line_no,
                                    description=description,
                                    evidence=line.strip()[:120],
                                    remediation=remediation,
                                )
                            )
        return findings
```

### Step 4: Wire and commit

Add to `GATE_CONTROL_MAP`:
```python
    "container":     ["CM-6", "CM-7", "SC-7", "SC-39", "AC-6", "SI-7", "AU-12", "SA-10", "SR-3"],
```

Add `ContainerGate` to `ALL_GATES` and `__all__`.

```bash
pytest tests/test_gates/test_container_gate.py -v
git add src/controlgate/gates/container_gate.py tests/test_gates/test_container_gate.py \
        src/controlgate/catalog.py src/controlgate/gates/__init__.py
git commit -m "feat: add Gate 18 — Container Security gate (container, CM-7/SC-7/SC-39/AC-6/SI-7)"
```

---

## Task 11: Full Test Suite Verification

### Step 1: Run the complete test suite

```bash
pytest tests/ -v --tb=short
```

Expected: All tests pass, including the existing 8 gate tests and 10 new gate tests.

### Step 2: Verify gate count

```bash
python -c "from controlgate.gates import ALL_GATES; print(f'{len(ALL_GATES)} gates loaded'); [print(f'  {g.gate_id}') for g in ALL_GATES]"
```

Expected output:
```
18 gates loaded
  secrets
  crypto
  iam
  sbom
  iac
  input_validation
  audit
  change_control
  deps
  api
  privacy
  resilience
  incident
  observability
  memsafe
  license
  aiml
  container
```

### Step 3: Final commit

```bash
git commit --allow-empty -m "chore: all 18 gates implemented and passing"
```

---

## Checklist

- [ ] Task 1: DepsGate (deps) — RA-5, SI-2, SA-12
- [ ] Task 2: APIGate (api) — SC-8, AC-3, SC-5, SI-10
- [ ] Task 3: PrivacyGate (privacy) — PT-2, PT-3, SC-28
- [ ] Task 4: ResilienceGate (resilience) — CP-9, CP-10, SI-13
- [ ] Task 5: IncidentGate (incident) — IR-4, IR-6, AU-6
- [ ] Task 6: ObservabilityGate (observability) — SI-4, AU-12
- [ ] Task 7: MemSafeGate (memsafe) — SI-16, CM-7
- [ ] Task 8: LicenseGate (license) — SA-4, SR-3
- [ ] Task 9: AIMLGate (aiml) — SI-10, SC-28, SR-3
- [ ] Task 10: ContainerGate (container) — CM-6, CM-7, SC-7, SC-39, AC-6, SI-7, AU-12
- [ ] Task 11: Full test suite passes
