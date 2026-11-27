import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('dast_report', Path(__file__).parents[1] / 'scripts/dast_report.py')
dast_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dast_report)


def report(risk):
    return {'site': [{'@host': 'calculator', '@port': '5000', 'alerts': [
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
