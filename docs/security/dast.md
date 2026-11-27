# Dynamic application security testing

The DAST workflow builds the Flask calculator from the checked-out commit and
scans that running application with ZAP. The target is always
`http://calculator:5000` on a disposable internal Docker network. Neither the
application nor the scanner publishes a host port. No Azure resources, Jenkins,
Java application, authenticated service or third-party site is a scan target.

## Run and inspect

Requirements: Git, Docker with Linux containers, Bash, GNU timeout and Python 3.

```bash
bash scripts/dast.sh baseline
bash scripts/dast.sh full
```

Each command creates a separate `.local/dast/<mode>` directory. Move an existing
directory before repeating the same command; evidence is never overwritten.
The scanner image is pinned by digest in `scripts/dast.sh`. The calculator uses
its existing application Dockerfile. Image builds and pulls need network access;
the running scan and application share an internal network with no external
egress. Scanner auto-updates are disabled for that isolated execution.

Baseline uses spidering and passive response analysis. Full uses spidering plus
an active scan of this disposable, stateless calculator. A shell timeout bounds
the scanner to ten minutes; timeout, scanner failure and malformed/missing reports
are errors, never successful scans. Cleanup runs on success and failure.

## Policy and evidence

The gate in `scripts/dast_report.py` fails on ZAP medium/high findings (risk codes
2 and 3). Low/informational findings remain visible for review. Native scanner
exit codes 0, 1 and 2 describe completed scans; the gate reads the report to apply
the severity policy. Other exit codes fail closed. A report must describe exactly
the expected calculator host and port.

There is one explicit applicability review in `.zap/stateless-csrf-review.json`:
rule 10202 on `/` and `/calculations`, for the stateless calculator only. It has
an owner, rationale, review deadline and a SHA-256 of the reviewed application
source. A changed application, another path/method, high-risk alert or expired
review blocks again. The original risk and evidence remain in both the raw ZAP
report and summary. This is not a rule-wide scanner exclusion or an enterprise
risk-acceptance approval.

Every run preserves the original ZAP HTML/JSON, scanner/application logs, and a
JSON/Markdown summary containing the checked-out commit, scanner digest, scan
mode, findings and gate decision. GitHub Actions retains these as artifacts for
30 days, including failed scans. Download reports before they expire. The
verification record below retains the run links and reviewed findings in Git.

An empty finding list establishes only that the configured scanner found nothing
in its explored scope. It does not establish complete route/input coverage,
exploitability, production hardening or absence of vulnerabilities. Successful
application tests remain a separate requirement.

## Verification record

Initial baseline: [run 45989702697](https://github.com/JeanneBM/devops-platform-lab-local/actions/runs/45989702697),
PR head `8cc4274170d7eac4591d51544b20fa34358a2180`, checked-out merge commit
`0cbe85877b4330a9acaf41b038f35515818f236d`, ZAP 2.17.0. The scanner completed
with native exit 2; the severity gate failed with exit 1 on four medium rules.
The original JSON and summary are retained under `evidence/2026-11-27/`.

| Rule | Initial risk | Review/action |
| --- | --- | --- |
| 10038 | Medium | Missing CSP; add a restrictive policy covering HTML and error responses |
| 10020 | Medium | Missing anti-clickjacking header; add DENY and CSP frame-ancestors none |
| 90003 | Medium | Third-party CSS without SRI; replace external/inline CSS with a local stylesheet |
| 10202 | Medium | No anti-CSRF token; reviewed as not applicable to this stateless, unauthenticated calculator; source-bound review expires 2026-12-27 |
| 10021 | Low | Missing nosniff; add X-Content-Type-Options to all responses |
| 10031 | Informational | Potential attribute reflection; form operation options are static, numeric inputs parsed and invalid input rejected; not a confirmed XSS vulnerability |

Remediation also sets no-store and no-referrer. Original application functionality
is retained, and tests cover headers on successful, error and static responses.
Baseline and active rerun results will be recorded after CI completes.

## References

- https://www.zaproxy.org/docs/docker/baseline-scan/
- https://www.zaproxy.org/docs/docker/full-scan/
- https://www.zaproxy.org/docs/alerts/
