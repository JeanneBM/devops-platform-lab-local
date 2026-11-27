# Dynamic application security testing

The reusable DAST workflow builds the Flask calculator from the checked-out commit and
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

The main CI workflow calls DAST after unit tests, alongside kind integration.
Its image-publishing job requires both integration and DAST to pass. DAST can
also be dispatched manually. Repository merge protection is a separate setting;
a failed check alone does not prevent an owner merging an unprotected branch.

The gate in `scripts/dast_report.py` fails on ZAP medium/high findings (risk codes
2 and 3). Low/informational findings remain visible for review. Native scanner
exit codes 0, 1 and 2 describe completed scans; the gate reads the report to apply
the severity policy. Other exit codes fail closed. A report must describe exactly
the expected calculator host and port. An active scan may also report its HTTPS
probe against that same host/port. All alerts from both reported origins are
retained; another hostname, port or a missing HTTP target is an error.

There is an explicit applicability review in `.zap/stateless-csrf-review.json`:
rule 10202 on `/` and `/calculations`, for the stateless calculator only. It has
an owner, rationale, review deadline and a SHA-256 of the reviewed application
source. `.zap/internal-http-review.json` separately records the observed HTTP-only
transport (10106) on `/`, confined to the internal network without published
ports, credentials or customer data. It is bound to both the application and
runner source and expires 2026-12-27; production TLS is not verified here.
A changed reviewed source, another path/method, high-risk alert or expired
review blocks again. The original risk and evidence remain in both the raw ZAP
report and summary. This is not a rule-wide scanner exclusion or an enterprise
risk-acceptance approval. The HTTP transport finding is a lab exception, while
the CSRF finding is a source-specific applicability decision.

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

[Run 45990489083](https://github.com/JeanneBM/devops-platform-lab-local/actions/runs/45990489083)
at PR head `eb18a5b130fef858abf83fd9de5d63002b0f2c36` verified the baseline
remediation: 10038, 10020, 90003 and 10021 were no longer reported. The CSRF
finding and informational 10031 remained visible.

Its first full scan completed (native scanner exit 2) and additionally reported
medium 10106, HTTP Only Site. The original gate returned ERROR because the report
included the scanner's HTTPS probe as a second site. The raw report and error
summary are retained as `first-full-*`. The parser now accepts only HTTP/HTTPS
entries for the same calculator host/port, retains all their alerts, and rejects
unexpected targets. The separate HTTP lab review documents the transport limit.
The final live CI results will be recorded after the corrected gate is rerun.

## Explaining the decisions

- SAST examines source code, SCA examines dependencies, and this DAST check sends
  HTTP requests to the running calculator. Baseline response analysis and active
  attack requests are distinct scan modes.
- The original stylesheet was fetched from a third-party CDN without SRI. Local
  CSS removes that browser dependency and allows a restrictive self-only style
  policy without permitting inline styles.
- A missing anti-CSRF token is an observed fact. Its security impact depends on
  what the action does and what user authority it uses. This specific form only
  returns arithmetic results; the reviewed code has no user session or saved
  state. Authentication or persistence requires a new review and suitable CSRF
  controls. The source hash prevents the existing review silently covering
  changed application code.
- A passing gate does not mean zero scanner alerts. The report retains the
  contextual medium findings, their reviews and informational findings. New
  unreviewed medium/high findings still fail.
- Report generation failure and a vulnerability finding are different outcomes;
  both prevent publishing, and both retain diagnostic evidence when available.

## References

- https://www.zaproxy.org/docs/docker/baseline-scan/
- https://www.zaproxy.org/docs/docker/full-scan/
- https://www.zaproxy.org/docs/alerts/
