"""Fail closed on incomplete scans and on ZAP medium/high findings."""
import argparse
from datetime import datetime, timezone, date
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit


def assess(report, scanner_exit, reviews=(), source_hashes=None, today=None):
    if scanner_exit not in (0, 1, 2):
        raise ValueError(f'Scanner failed or timed out (exit {scanner_exit}).')
    if not isinstance(report, dict):
        raise ValueError('Expected a ZAP report object.')
    sites = report.get('site')
    if not isinstance(sites, list) or not sites:
        raise ValueError('Expected the scanned calculator site.')
    alerts = []
    origins = set()
    for site in sites:
        if not isinstance(site, dict):
            raise ValueError('Invalid scanned site.')
        origin = site.get('@name')
        if (origin not in ('http://calculator:5000', 'https://calculator:5000')
                or site.get('@host') != 'calculator' or str(site.get('@port')) != '5000'
                or origin in origins):
            raise ValueError('Report contains an unexpected or duplicate target.')
        origins.add(origin)
        if not isinstance(site.get('alerts'), list):
            raise ValueError('Report has no alert list.')
        alerts.extend(site['alerts'])
    if 'http://calculator:5000' not in origins:
        raise ValueError('Report does not contain the HTTP calculator target.')
    findings = []
    for alert in alerts:
        risk = int(alert['riskcode'])
        if risk not in range(4):
            raise ValueError('Unrecognized ZAP risk code.')
        finding = {
            'rule': str(alert['pluginid']), 'name': alert['name'],
            'risk': risk, 'instances': alert.get('instances', []),
            'disposition': 'blocking' if risk >= 2 else 'review',
        }
        # Source-bound lab reviews retain the original rule, risk and evidence.
        for review in reviews:
            if finding['rule'] != review['rule'] or risk > 2:
                continue
            current_date = today or datetime.now(timezone.utc).date()
            scope_matches = bool(finding['instances']) and all(
                urlsplit(i['uri']).scheme == 'http'
                and urlsplit(i['uri']).netloc == 'calculator:5000'
                and (urlsplit(i['uri']).path or '/') in review['paths']
                and i['method'] in review['methods']
                for i in finding['instances']
            )
            source_matches = bool(review['source_sha256']) and all(
                (source_hashes or {}).get(path) == digest
                for path, digest in review['source_sha256'].items()
            )
            if (scope_matches and source_matches
                    and current_date < date.fromisoformat(review['review_by'])
                    and review['owner'] and review['reason']):
                finding.update(disposition=review['classification'], review=review)
        findings.append(finding)
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--scanner-exit', type=int, required=True)
    parser.add_argument('--mode', choices=('baseline', 'full'), required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    summary = {
        'mode': args.mode, 'target': 'http://calculator:5000',
        'source_commit': args.commit, 'scanner_image': args.image,
        'scanner_exit': args.scanner_exit,
        'policy': 'Fail on medium/high unless covered by the current, scoped lab review.',
    }
    try:
        report = json.loads(args.report.read_text())
        root = Path(__file__).resolve().parents[1]
        reviews = []
        allowed = {'10202': ('not-applicable', {'src/python/app.py'}),
                   '10106': ('isolated-lab-transport', {'src/python/app.py', 'scripts/dast.sh'})}
        for filename in ('stateless-csrf-review.json', 'internal-http-review.json'):
            review_path = root / '.zap' / filename
            if review_path.exists():
                review = json.loads(review_path.read_text())
                expected = allowed.get(review['rule'])
                if (not expected or review['classification'] != expected[0]
                        or set(review['source_sha256']) != expected[1]):
                    raise ValueError('Unsupported lab finding review.')
                reviews.append(review)
        source_hashes = {path: hashlib.sha256((root / path).read_bytes()).hexdigest()
                         for path in ('src/python/app.py', 'scripts/dast.sh')}
        findings = assess(report, args.scanner_exit, reviews, source_hashes)
        blocking = [f for f in findings if f['disposition'] == 'blocking']
        summary.update(status='FAIL' if blocking else 'PASS',
                       zap_version=report.get('@version'), findings=findings,
                       reported_origins=[site['@name'] for site in report['site']],
                       blocking_rules=[f['rule'] for f in blocking])
        status = 1 if blocking else 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        summary.update(status='ERROR', error=str(exc))
        status = 2
    args.report.parent.mkdir(parents=True, exist_ok=True)
    (args.report.parent / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    lines = [f"## ZAP {args.mode}: {summary['status']}", '',
             f"Source commit: `{args.commit}`", '', summary['policy'], '']
    if 'error' in summary:
        lines.append(f"Scan error: {summary['error']}")
    else:
        lines.extend(['| Rule | Risk | Finding | Disposition |', '| --- | --- | --- | --- |'])
        for finding in summary['findings']:
            lines.append(f"| {finding['rule']} | {finding['risk']} | {finding['name']} | {finding['disposition']} |")
    (args.report.parent / 'summary.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps(summary, indent=2))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
