"""Fail closed on incomplete scans and on ZAP medium/high findings."""
import argparse
import json
from pathlib import Path


def assess(report, scanner_exit):
    if scanner_exit not in (0, 1, 2):
        raise ValueError(f'Scanner failed or timed out (exit {scanner_exit}).')
    sites = report.get('site')
    if not isinstance(sites, list) or len(sites) != 1:
        raise ValueError('Expected exactly one scanned site.')
    site = sites[0]
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
        findings.append({
            'rule': str(alert['pluginid']), 'name': alert['name'],
            'risk': risk, 'instances': alert.get('instances', []),
        })
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
        'scanner_exit': args.scanner_exit, 'policy': 'Fail on medium/high (risk >= 2).',
    }
    try:
        report = json.loads(args.report.read_text())
        findings = assess(report, args.scanner_exit)
        blocking = [f for f in findings if f['risk'] >= 2]
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
        lines.extend(['| Rule | Risk | Finding |', '| --- | --- | --- |'])
        for finding in summary['findings']:
            lines.append(f"| {finding['rule']} | {finding['risk']} | {finding['name']} |")
    (args.report.parent / 'summary.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps(summary, indent=2))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
