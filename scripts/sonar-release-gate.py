#!/usr/bin/env python3
"""Require a successful Sonar analysis of this commit and >=90% overall coverage."""
import json
import argparse
import os
import pathlib
import time
import urllib.parse
import urllib.request
from decimal import Decimal


def require_coverage(value):
    coverage = Decimal(value)
    if not coverage.is_finite() or not Decimal(90) <= coverage <= Decimal(100):
        raise ValueError(f'Overall Sonar coverage {value}% is below the 90% release threshold')
    return coverage


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--published', action='store_true', help='Use the isolated consumer analysis already published for this commit')
    args = parser.parse_args(argv)
    host = os.environ.get('SONAR_HOST_URL', 'https://sonarcloud.io').rstrip('/')
    if urllib.parse.urlparse(host).scheme != 'https':
        raise SystemExit('Sonar URL must use HTTPS')
    token = os.environ['SONAR_TOKEN']
    if not token:
        raise SystemExit('SONAR_TOKEN is required')
    project = (json.loads(pathlib.Path('.github/sonar.json').read_text())['project_key']
               if args.published else os.environ['SONAR_PROJECT_KEY'])
    if args.published and host != 'https://sonarcloud.io':
        raise SystemExit('Published analysis uses the shared SonarCloud consumer')
    revision = os.environ['GITHUB_SHA']

    def get(endpoint, **params):
        request = urllib.request.Request(host + '/api/' + endpoint + '?' + urllib.parse.urlencode(params), headers={'Authorization': 'Bearer ' + token})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    def latest_analysis():
        return get('project_analyses/search', project=project, branch='main', ps=1)['analyses']

    if args.published:
        analyses = latest_analysis()
        if not analyses or analyses[0].get('revision') != revision:
            raise SystemExit('No published main analysis for this release commit; wait for SonarCloud and retry')
        analysis = analyses[0]['key']
    else:
        task = dict(line.split('=', 1) for line in pathlib.Path('.scannerwork/report-task.txt').read_text().splitlines() if '=' in line)
        deadline = time.monotonic() + 600
        while True:
            result = get('ce/task', id=task['ceTaskId'])['task']
            if result['status'] == 'SUCCESS':
                break
            if result['status'] in {'FAILED', 'CANCELED'} or time.monotonic() >= deadline:
                raise SystemExit('Sonar analysis failed or timed out')
            time.sleep(5)
        analysis = result['analysisId']
    gate = get('qualitygates/project_status', analysisId=analysis)['projectStatus']
    if gate['status'] != 'OK':
        raise SystemExit('Sonar quality gate did not pass')

    def check_identity():
        analyses = latest_analysis()
        if not analyses or analyses[0]['key'] != analysis or analyses[0].get('revision') != revision:
            raise SystemExit('Sonar results are stale or a concurrent analysis replaced this commit')

    check_identity()
    measures = get('measures/component', component=project, branch='main', metricKeys='coverage,lines_to_cover')['component']['measures']
    metrics = {item['metric']: item['value'] for item in measures}
    if Decimal(metrics.get('lines_to_cover', '0')) <= 0:
        raise SystemExit('Sonar returned no executable source lines')
    coverage = require_coverage(metrics['coverage'])
    check_identity()
    print(f'Sonar analysis {analysis}: overall coverage {coverage}% passes 90% release threshold')


if __name__ == '__main__':
    main()
