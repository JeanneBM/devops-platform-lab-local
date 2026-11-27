import importlib.util
from datetime import date
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('dast_report', Path(__file__).parents[1] / 'scripts/dast_report.py')
dast_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dast_report)


def report(risk):
    return {'site': [{'@name': 'http://calculator:5000', '@host': 'calculator', '@port': '5000', 'alerts': [
        {'pluginid': '10038', 'name': 'CSP missing', 'riskcode': str(risk), 'instances': []}
    ]}]}


def test_medium_and_high_findings_remain_blocking():
    for risk in (2, 3):
        findings = dast_report.assess(report(risk), 2)
        assert [f for f in findings if f['risk'] >= 2]


def test_low_findings_are_retained_for_review():
    findings = dast_report.assess(report(1), 2)
    assert findings[0]['risk'] == 1
    assert not [f for f in findings if f['risk'] >= 2]


@pytest.mark.parametrize('exit_code', [3, 124, 125, 137])
def test_scanner_errors_and_timeouts_never_pass(exit_code):
    with pytest.raises(ValueError):
        dast_report.assess(report(0), exit_code)


@pytest.mark.parametrize('data', [{}, {'site': []}, {'site': [{'@host': 'other', '@port': '5000', 'alerts': []}]}])
def test_missing_or_wrong_target_never_passes(data):
    with pytest.raises(ValueError):
        dast_report.assess(data, 0)


def csrf_review():
    return {'rule': '10202', 'paths': ['/', '/calculations'], 'methods': ['GET', 'POST'],
            'source_sha256': {'src/python/app.py': 'reviewed-source'},
            'classification': 'not-applicable', 'review_by': '2026-12-27',
            'owner': 'JeanneBM', 'reason': 'Stateless calculation, no user authority or saved state.'}


def csrf_report(path='/calculations', risk=2):
    data = report(risk)
    alert = data['site'][0]['alerts'][0]
    alert.update(pluginid='10202', name='Absence of Anti-CSRF Tokens', instances=[
        {'uri': 'http://calculator:5000' + path, 'method': 'POST'}
    ])
    return data


def test_review_retains_original_risk_and_evidence():
    finding = dast_report.assess(csrf_report(), 2, [csrf_review()], {'src/python/app.py': 'reviewed-source'}, date(2026, 11, 27))[0]
    assert finding['risk'] == 2
    assert finding['instances']
    assert finding['disposition'] == 'not-applicable'


@pytest.mark.parametrize('path,risk,source,today', [
    ('/new-action', 2, 'reviewed-source', date(2026, 11, 27)),
    ('/calculations', 3, 'reviewed-source', date(2026, 11, 27)),
    ('/calculations', 2, 'changed-source', date(2026, 11, 27)),
    ('/calculations', 2, 'reviewed-source', date(2026, 12, 27)),
])
def test_review_never_covers_other_paths_high_risk_changed_code_or_expiry(path, risk, source, today):
    finding = dast_report.assess(csrf_report(path, risk), 2, [csrf_review()], {'src/python/app.py': source}, today)[0]
    assert finding['disposition'] == 'blocking'


def test_full_scan_https_probe_is_allowed_without_discarding_its_alerts():
    data = report(1)
    data['site'].append({'@name': 'https://calculator:5000', '@host': 'calculator', '@port': '5000',
                         'alerts': [{'pluginid': '123', 'name': 'Example high finding', 'riskcode': '3'}]})
    findings = dast_report.assess(data, 2)
    assert any(f['risk'] == 3 and f['disposition'] == 'blocking' for f in findings)


@pytest.mark.parametrize('origin,host,port', [
    ('http://other:5000', 'other', '5000'),
    ('https://calculator:443', 'calculator', '443'),
])
def test_additional_unexpected_target_is_not_silently_ignored(origin, host, port):
    data = report(0)
    data['site'].append({'@name': origin, '@host': host, '@port': port, 'alerts': []})
    with pytest.raises(ValueError):
        dast_report.assess(data, 0)


def test_http_lab_review_requires_the_reviewed_isolation_script():
    data = csrf_report('/', 2)
    data['site'][0]['alerts'][0].update(pluginid='10106', name='HTTP Only Site')
    review = csrf_review()
    review.update(rule='10106', classification='isolated-lab-transport',
                  source_sha256={'src/python/app.py': 'app', 'scripts/dast.sh': 'isolated-runner'})
    source = {'src/python/app.py': 'app', 'scripts/dast.sh': 'isolated-runner'}
    assert dast_report.assess(data, 2, [review], source, date(2026, 11, 27))[0]['disposition'] == 'isolated-lab-transport'
    source['scripts/dast.sh'] = 'changed-runner'
    assert dast_report.assess(data, 2, [review], source, date(2026, 11, 27))[0]['disposition'] == 'blocking'
