import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('sonar_gate', pathlib.Path(__file__).resolve().parents[1] / 'scripts/sonar-release-gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class GateTests(unittest.TestCase):
    def test_boundary(self):
        self.assertEqual(gate.require_coverage('90.0'), 90)
        self.assertEqual(gate.require_coverage('100'), 100)

    def test_rejects_low_or_invalid_values(self):
        for value in ['89.99', 'NaN', 'Infinity', '101', '-1']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.require_coverage(value)

    def exercise_analysis(self, coverage='90', revision='source', status='OK', task_status='SUCCESS', analyses=None, lines='100', published=False, replacement=False):
        import io
        import json
        import os
        import tempfile
        from unittest.mock import patch

        analysis_reads = 0

        def response(request, timeout):
            nonlocal analysis_reads
            url = request.full_url
            if '/ce/task?' in url:
                data = {'task': {'status': task_status, 'analysisId': 'analysis'}}
            elif '/qualitygates/project_status?' in url:
                data = {'projectStatus': {'status': status}}
            elif '/project_analyses/search?' in url:
                analysis_reads += 1
                data = {'analyses': analyses if analyses is not None else [{'key': 'analysis', 'revision': revision}]}
                if replacement and analysis_reads > 1:
                    data = {'analyses': [{'key': 'concurrent', 'revision': 'another'}]}
            elif '/measures/component?' in url:
                data = {'component': {'measures': [{'metric': 'coverage', 'value': coverage}, {'metric': 'lines_to_cover', 'value': lines}]}}
            else:
                raise AssertionError('Unexpected API endpoint')
            return io.BytesIO(json.dumps(data).encode())

        with tempfile.TemporaryDirectory() as temporary:
            report = pathlib.Path(temporary) / 'task.txt'
            report.write_text('ceTaskId=task\n')
            original_read = pathlib.Path.read_text

            def read(path, *args, **kwargs):
                return original_read(report if str(path) == '.scannerwork/report-task.txt' else path, *args, **kwargs)

            with patch.dict(os.environ, {'SONAR_TOKEN': 'test', 'SONAR_PROJECT_KEY': 'project', 'GITHUB_SHA': 'source', 'SONAR_HOST_URL': 'https://sonarcloud.io'}), patch.object(pathlib.Path, 'read_text', read), patch.object(gate.urllib.request, 'urlopen', response):
                gate.main(['--published'] if published else [])

    def test_exact_analysis_passes(self):
        self.exercise_analysis()

    def test_wrong_source_and_stale_analysis_fail(self):
        with self.assertRaises(SystemExit):
            self.exercise_analysis(revision='another-commit')
        with self.assertRaises(SystemExit):
            self.exercise_analysis(analyses=[{'key': 'stale', 'revision': 'source'}])

    def test_failed_gate_and_failed_task_fail(self):
        with self.assertRaises(SystemExit):
            self.exercise_analysis(status='ERROR')
        with self.assertRaises(SystemExit):
            self.exercise_analysis(task_status='FAILED')

    def test_low_coverage_and_no_lines_fail(self):
        with self.assertRaises(ValueError):
            self.exercise_analysis(coverage='89.9')
        with self.assertRaises(SystemExit):
            self.exercise_analysis(lines='0')

    def test_published_release_analysis(self):
        self.exercise_analysis(published=True)
        for options in ({'revision': 'other'}, {'analyses': []}, {'status': 'ERROR'},
                        {'replacement': True}, {'lines': '0'}):
            with self.subTest(options=options), self.assertRaises(SystemExit):
                self.exercise_analysis(published=True, **options)
        with self.assertRaises(ValueError):
            self.exercise_analysis(published=True, coverage='89.99')

    def test_credentials_and_host_are_checked_before_network_access(self):
        import os
        from unittest.mock import patch

        for environment in (
            {'SONAR_TOKEN': '', 'SONAR_HOST_URL': 'https://sonarcloud.io'},
            {'SONAR_TOKEN': 'test', 'SONAR_HOST_URL': 'http://sonarcloud.io'},
            {'SONAR_TOKEN': 'test', 'SONAR_HOST_URL': 'https://another.invalid'},
        ):
            with self.subTest(environment=environment), patch.dict(os.environ, environment), \
                    patch.object(gate.urllib.request, 'urlopen') as network:
                with self.assertRaises(SystemExit):
                    gate.main(['--published'])
                network.assert_not_called()

    def test_pending_analysis_cannot_wait_past_deadline(self):
        from unittest.mock import patch

        with patch.object(gate.time, 'monotonic', side_effect=[0, 601]), \
                self.assertRaises(SystemExit):
            self.exercise_analysis(task_status='PENDING')

    def test_cli_rejects_missing_credentials(self):
        import os
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, str(pathlib.Path(gate.__file__)), '--published'],
            env={**os.environ, 'SONAR_TOKEN': '', 'SONAR_HOST_URL': 'https://sonarcloud.io'},
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SONAR_TOKEN is required', result.stderr)
