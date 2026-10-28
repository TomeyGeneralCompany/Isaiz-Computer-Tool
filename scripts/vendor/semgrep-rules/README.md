# Vendored Semgrep community rules

Source: https://github.com/semgrep/semgrep-rules

The manifest pins the upstream commit and SHA-256 of each unchanged rule and
test fixture. The 24 rules run with Semgrep Community Edition 1.99.0, offline,
without an account. Upstream license is retained in LICENSE. Fixtures are only
parsed by Semgrep's test runner; they are not application code or executed tests.

Coverage includes Python Flask/Django, JavaScript Express/SQL clients and Java
servlet/Spring APIs, plus generic dangerous operations. These are candidate
detectors, not proof of a vulnerability. They do not provide a general executor
for arbitrary framework applications. Existing reproduction gates still apply.

Validate provenance with `python3 scripts/check-vendored-rules.py`. Run upstream
positive and negative annotations with:

```
SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 .venv-static/bin/semgrep --test --config scripts/vendor/semgrep-rules scripts/vendor/semgrep-rules
```

Do not update the rules without updating their upstream fixtures and manifest
and passing these tests against the pinned free engine.
