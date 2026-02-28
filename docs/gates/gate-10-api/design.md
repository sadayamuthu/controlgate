# Gate 10 — API Security Gate

**gate_id:** `api`
**NIST Controls:** SC-8, AC-3, SC-5, SI-10
**Priority:** High

---

## Purpose

Guards against insecure API configuration patterns that are commonly exploited in web application attacks. TLS verification bypasses expose services to man-in-the-middle interception; overly permissive CORS policies allow attacker-controlled origins to make credentialed cross-site requests; API credentials placed in URL query parameters are captured in server access logs, browser history, and proxy caches; and GraphQL introspection left enabled in production hands attackers a complete map of the API surface. By flagging these patterns at diff time, the gate ensures that insecure API configurations are caught before they reach a deployed environment.

---

## What This Gate Detects

| Detection | Why It Matters | NIST Control |
|---|---|---|
| `verify=False` in HTTP client calls | Disabling TLS certificate verification removes the only protection against man-in-the-middle attacks on encrypted channels | SC-8 |
| `CORS_ORIGIN_ALLOW_ALL = True` or `allow_all_origins = True` | Framework-level wildcard CORS setting permits any domain to make credentialed cross-origin requests, undermining same-origin isolation | AC-3 |
| `Access-Control-Allow-Origin: *` header | Wildcard origin in the CORS response header allows any website to read API responses | AC-3 |
| `Access-Control-Allow-Credentials: true` with any origin | Combining credentialed CORS with a wildcard or permissive origin creates a CSRF/CORS bypass risk by forwarding session cookies to attacker-controlled pages | AC-3 |
| API key or token in URL query parameter (`?api_key=`, `?token=`, `?access_token=`, `?secret=`) | Credentials embedded in URLs appear in server access logs, browser history, CDN logs, and referrer headers — where they are visible to non-security personnel | SC-8 |
| `GRAPHQL_INTROSPECTION = True` or `graphiql = True` | GraphQL introspection and the GraphiQL IDE expose the full type system and query structure of the API, giving attackers a complete reconnaissance tool in production | AC-3 |

---

## Scope

- **Scans:** added lines in git diffs
- **File types targeted:** all files

---

## Known Limitations

- Does not scan deleted or removed lines
- Does not perform cross-file analysis
- The `Access-Control-Allow-Credentials` pattern fires on any added line containing the header value `true` regardless of whether a wildcard `Access-Control-Allow-Origin` header is set in the same response; the combination check is heuristic, not semantic
- The query-parameter pattern is regex-based and fires on URL strings in any file type, including documentation and test fixtures that may use example URLs with dummy credentials
- Does not detect TLS verification issues expressed through framework-level settings other than the `verify=False` keyword argument (e.g., environment variables that suppress verification)

---

## NIST Control Mapping

| Control ID | Title | How This Gate Addresses It |
|---|---|---|
| SC-8 | Transmission Confidentiality and Integrity | Detects `verify=False` which disables TLS certificate validation and exposes transmissions to interception, and detects API credentials placed in URL query parameters where they can leak through log channels |
| AC-3 | Access Enforcement | Detects wildcard and overly permissive CORS configurations that allow unauthorized origins to access protected API resources, and detects GraphQL introspection that bypasses access controls by revealing the full API schema |
| SC-5 | Denial of Service Protection | Declared in `mapped_control_ids`; no patterns currently emitted — rate-limiting and DoS detection are deferred (see Known Debt in the implementation reference) |
| SI-10 | Information Input Validation | Declared in `mapped_control_ids`; no patterns currently emitted — API input schema validation checks are deferred (see Known Debt in the implementation reference) |
