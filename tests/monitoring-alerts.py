#!/usr/bin/env python3
"""Generate promtool scenarios for a reference or transitional deployment rule.

Usage: python3 tests/monitoring-alerts.py MANIFEST OUTPUT_DIRECTORY
Then: promtool check rules OUTPUT_DIRECTORY/rules.yaml
      promtool test rules OUTPUT_DIRECTORY/tests.yaml
Requires PyYAML. Tests use Prometheus counters, including initially absent series.
"""
import sys
from pathlib import Path

import yaml

manifest = yaml.safe_load(Path(sys.argv[1]).read_text())
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
groups = manifest['spec']['groups']
rules = {r['alert']: r for g in groups for r in g['rules']}
prefixes = ['bathysign']
if 'android_signer_operations_total' in str(groups):
    prefixes.append('android_signer')
tests = []
labels = {'job': 'signer', 'instance': 'signer:443'}


def series(prefix, name, values, **extra):
    fields = ','.join(f'{k}="{v}"' for k, v in (labels | extra).items())
    return {'series': f'{prefix}_{name}{{{fields}}}', 'values': values}


def check(name, minute, firing=False, operation=None):
    expected = []
    if firing:
        alert_labels = labels | {'severity': rules[name]['labels']['severity']}
        if operation:
            alert_labels['operation'] = operation
        if name == 'AndroidSignerTrustPersistenceFailures':
            alert_labels.update(operation='trust_commit', outcome='failure')
        annotations = {
            k: v.replace('{{ $labels.operation }}', operation or '')
            for k, v in rules[name]['annotations'].items()
        }
        expected.append({'exp_labels': alert_labels, 'exp_annotations': annotations})
    return {'eval_time': f'{minute}m', 'alertname': name, 'exp_alerts': expected}


def case(prefix, name, inputs, checks):
    tests.append({'name': f'{prefix}: {name}', 'interval': '1m',
                  'input_series': inputs, 'alert_rule_test': checks})


polling = 'AndroidSignerLedgerPollingStalled'
task = 'AndroidSignerTaskFailures'
timeout = 'AndroidSignerNetworkTimeouts'
for p in prefixes:
    def op(operation, outcome, values):
        return series(p, 'operations_total', values, operation=operation, outcome=outcome)

    # A single failure appearing for the first time must stay quiet, including
    # timeout and response-body measurements for the same failed request.
    case(p, 'one recovered poll', [
        op('ledger_claim', 'success', '100+12x20'),
        op('ledger_claim', 'failure', '_ _ 1+0x18'),
        op('network_body', 'failure', '_ _ 1+0x18'),
        op('network_timeout', 'failure', '_ _ 1+0x18'),
    ], [check(a, m) for a in (polling, task, timeout) for m in (2, 4, 10, 18)])
    case(p, 'established polling stops and recovers', [
        op('ledger_claim', 'success', '100+12x3 136+0x9 148+12x8'),
        op('ledger_claim', 'failure', '0+0x3 1+12x9 109+0x8'),
    ], [check(polling, 7), check(polling, 11, True), check(polling, 15),
        check(task, 11)])
    case(p, 'collector unavailable from startup', [
        op('ledger_claim', 'failure', '1+12x15'),
    ], [check(polling, 1), check(polling, 3, True)])
    case(p, 'active signing legitimately pauses polling', [
        op('ledger_claim', 'success', '100+0x20'),
        op('ledger_claim', 'failure', '1+0x20'),
        series(p, 'job_active', '1+0x20'),
    ], [check(polling, 10), check(polling, 20)])
    case(p, 'counter reset with healthy polling', [
        op('ledger_claim', 'success', '100+12x3 0+12x16'),
        op('ledger_claim', 'failure', '1+0x3 0+0x16'),
    ], [check(polling, 5), check(polling, 10)])
    case(p, 'repeated timeouts', [op('network_timeout', 'failure', '0 6+0x15')],
         [check(timeout, 1, True), check(task, 1)])
    case(p, 'first observed timeout burst', [op('network_timeout', 'failure', '_ 6+0x15')],
         [check(timeout, 1, True)])
    case(p, 'five timeouts remain below notification threshold', [
        op('network_timeout', 'failure', '0 5+0x15'),
    ], [check(timeout, 1), check(timeout, 10)])
    for operation in ('verify_inputs', 'sign_outputs', 'publish_outputs', 'trust_refresh'):
        case(p, f'{operation} failure remains immediate', [
            op(operation, 'failure', '_ 1+0x15'),
        ], [check(task, 1, True, operation)])
    case(p, 'trust persistence failure remains critical', [
        op('trust_commit', 'failure', '_ 1+0x15'),
    ], [check('AndroidSignerTrustPersistenceFailures', 1, True)])

if len(prefixes) == 2:
    case('mixed', 'targets cannot hide each other', [
        series('bathysign', 'operations_total', '1+12x15', operation='ledger_claim', outcome='failure'),
        {'series': 'bathysign_operations_total{job="other",instance="other:443",operation="ledger_claim",outcome="success"}',
         'values': '100+12x15'},
    ], [check(polling, 3, True)])

(out / 'rules.yaml').write_text(yaml.safe_dump({'groups': groups}, sort_keys=False))
(out / 'tests.yaml').write_text(yaml.safe_dump({
    'rule_files': ['rules.yaml'], 'evaluation_interval': '1m', 'tests': tests,
}, sort_keys=False))
print(f'Generated {len(tests)} scenarios in {out}')
