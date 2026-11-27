"""Fail closed on incomplete scans and on ZAP medium/high findings."""
import argparse
from datetime import datetime, timezone, date
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit


def assess(report, scanner_exit, review=None, source_hash=None, today=None):
    if scanner_exit not in (0, 1, 2):
        raise ValueError(f'Scanner failed or timed out (exit {scanner_exit}).')
    if not isinstance(report, dict):
        raise ValueError('Expected a ZAP report object.')
    sites = report.get('site')
    if not isinstance(sites, list) or len(sites) != 1:
        raise ValueError('Expected exactly one scanned site.')
    site = sites[0]
    if not isinstance(site, dict):
        raise ValueError('Invalid scanned site.')
    if site.get('@host') != 'calculator' or str(site.get('@port')) != '5000':
        raise ValueError('Report does not describe the disposable calculator.')
    alerts = site.get('alerts')
    if not isinstance(alerts, list):
        raise ValueError('Report has no alert list.')
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
        # One reviewed, source-bound lab finding; never suppress a scanner rule globally.
        if review and finding['rule'] == review['rule'] and risk <= 2:
            current_date = today or datetime.now(timezone.utc).date()
            scope_matches = bool(finding['instances']) and all(
                urlsplit(i['uri']).scheme == 'http'
                and urlsplit(i['uri']).netloc == 'calculator:5000'
                and (urlsplit(i['uri']).path or '/') in review['paths']
                and i['method'] in review['methods']
                for i in finding['instances']
            )
            if (scope_matches and source_hash == review['application_sha256']
                    and current_date < date.fromisoformat(review['review_by'])
                    and review['owner'] and review['reason']):
                finding.update(disposition='not-applicable-to-stateless-lab', review=review)
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
        review_path = root / '.zap/stateless-csrf-review.json'
        review = json.loads(review_path.read_text()) if review_path.exists() else None
        if review and (review['rule'] != '10202' or review['classification'] != 'not-applicable'):
            raise ValueError('Unsupported lab finding review.')
        source_hash = hashlib.sha256((root / 'src/python/app.py').read_bytes()).hexdigest()
        findings = assess(report, args.scanner_exit, review, source_hash)
        blocking = [f for f in findings if f['disposition'] == 'blocking']
        summary.update(status='FAIL' if blocking else 'PASS',
                       zap_version=report.get('@version'), findings=findings,
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
