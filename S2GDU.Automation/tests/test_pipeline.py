#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).parents[1]))
import pipeline


class PipelineBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.jobdir = self.root / 'jobs/job1'
        self.jobdir.mkdir(parents=True)
        (self.root / 'tools/s2gdu').mkdir(parents=True)
        (self.root / 'tools/s2gdu/S2GDU').write_bytes(b'binary')
        (self.root / 'seed').mkdir()
        (self.root / 'seed/signatures.jsonc').write_text('{}')
        self.jobfile = self.jobdir / 'job.json'

    def write_job(self, request):
        self.jobfile.write_text(json.dumps({'Id': 'job1', 'Request': request}))

    def run_pipeline(self, release, downloads, imports, backtracks, exports, publishes, noops):
        def fake_resolve(root, cache, requested):
            return 'newtag'
        def fake_previous(exclude_tag, asset_name):
            self.assertEqual(exclude_tag, 'gd-newtag')
            self.assertEqual(asset_name, 'clues.7z')
            return release
        def fake_download(url, target):
            downloads.append(url)
            target.write_text(json.dumps({'dumpsTag': release['_metadata_tag']}))
        def fake_run_import(root, job, jobdir, input_dir, seed_file, clues_dir, binary_regex):
            imports.append(binary_regex)
            (clues_dir / 'server.gdu.pb').write_bytes(b'clue')
        def fake_run_backtrack(root, job, jobdir, input_dir, previous_clues_dir, clues_dir, binary_regex):
            backtracks.append(binary_regex)
            (clues_dir / 'server.gdu.pb').write_bytes(b'clue')
            (clues_dir / 'server.report.json').write_text(json.dumps({'total': 1}))
        def fake_run_export(root, clues_dir, out_dir):
            exports.append(out_dir.name)
            out_dir.mkdir()
            (out_dir / 'signatures.jsonc').write_text('{}')
            (out_dir / 'offsets.jsonc').write_text('{}')
        def fake_compress(archive, files, base_dir=None):
            archive.write_bytes(b'7z')
        def fake_publish(jobdir, tag, title, files, notes=None):
            publishes.append((tag, title))
            return {'url': 'https://github.com/test/release', 'tag': tag, 'id': 1,
                    'assets': [{'name': p.name, 'url': 'https://github.com/test/' + p.name, 'sha256': 'x', 'bytes': 1} for p in files]}
        def fake_cleanup(jobdir):
            pass
        def fake_write_noop(jobdir, release):
            noops.append(release['tag_name'])
            pipeline.atomic_json(jobdir / 'publish_receipt.json', {'url': release['html_url'], 'tag': release['tag_name'], 'id': release['id'], 'noop': True, 'assets': []})
        with patch.object(pipeline, 'resolve_dumps_tag', fake_resolve), \
             patch.object(pipeline, 'previous_release', fake_previous), \
             patch.object(pipeline, 'download', fake_download), \
             patch.object(pipeline, 'run_import', fake_run_import), \
             patch.object(pipeline, 'run_backtrack', fake_run_backtrack), \
             patch.object(pipeline, 'run_export', fake_run_export), \
             patch.object(pipeline, 'compress', fake_compress), \
             patch.object(pipeline, 'publish', fake_publish), \
             patch.object(pipeline, 'cleanup_payload', fake_cleanup), \
             patch.object(pipeline, 'write_noop_receipt', fake_write_noop), \
             patch.object(pipeline, 'check_publish_access', lambda: None):
            pipeline.pipeline(self.root, self.jobfile)

    def test_first_release_has_no_baseline_and_runs_import(self):
        self.write_job({'DumpsTag': None, 'PublishRelease': True})
        downloads, imports, backtracks, exports, publishes, noops = [], [], [], [], [], []
        self.run_pipeline(None, downloads, imports, backtracks, exports, publishes, noops)
        self.assertEqual(len(imports), 1)
        self.assertEqual(len(backtracks), 0)
        self.assertEqual(exports, ['gamedata'])
        self.assertEqual(len(publishes), 1)
        self.assertEqual(publishes[0][0], 'gd-newtag')
        self.assertEqual(noops, [])
        metadata = json.loads((self.jobdir / 'release.json').read_text())
        self.assertIsNone(metadata['baselineDumpsTag'])
        self.assertEqual(metadata['dumpsTag'], 'newtag')

    def test_changed_tag_runs_backtrack_against_baseline(self):
        self.write_job({'DumpsTag': None, 'PublishRelease': True})
        release = {'tag_name': 'gd-oldtag', 'html_url': 'https://github.com/test/old', 'id': 1,
                   'assets': [{'name': 'clues.7z', 'url': 'https://api/clues'}, {'name': 'release.json', 'url': 'https://api/meta'}],
                   '_metadata_tag': 'oldtag'}
        downloads, imports, backtracks, exports, publishes, noops = [], [], [], [], [], []
        with patch.object(pipeline, 'run', lambda *a, **k: None):
            self.run_pipeline(release, downloads, imports, backtracks, exports, publishes, noops)
        self.assertEqual(len(backtracks), 1)
        self.assertEqual(len(imports), 0)
        self.assertEqual(len(publishes), 1)
        metadata = json.loads((self.jobdir / 'release.json').read_text())
        self.assertEqual(metadata['baselineDumpsTag'], 'oldtag')
        self.assertIn('server', metadata['reports'])
        self.assertEqual(noops, [])

    def test_unchanged_tag_finishes_as_noop(self):
        self.write_job({'DumpsTag': None, 'PublishRelease': True})
        release = {'tag_name': 'gd-newtag-baseline', 'html_url': 'https://github.com/test/old', 'id': 1,
                   'assets': [{'name': 'clues.7z', 'url': 'https://api/clues'}, {'name': 'release.json', 'url': 'https://api/meta'}],
                   '_metadata_tag': 'newtag'}
        downloads, imports, backtracks, exports, publishes, noops = [], [], [], [], [], []
        self.run_pipeline(release, downloads, imports, backtracks, exports, publishes, noops)
        self.assertEqual(imports, [])
        self.assertEqual(backtracks, [])
        self.assertEqual(publishes, [])
        self.assertEqual(noops, ['gd-newtag-baseline'])
        receipt = json.loads((self.jobdir / 'publish_receipt.json').read_text())
        self.assertTrue(receipt['noop'])
        self.assertFalse((self.jobdir / 'release.json').exists())

    def test_diagnostic_job_ignores_noop_shortcut_even_with_same_tag(self):
        self.write_job({'DumpsTag': None, 'PublishRelease': False, 'BinaryRegex': 'server'})
        release = {'tag_name': 'gd-newtag-baseline', 'html_url': 'https://github.com/test/old', 'id': 1,
                   'assets': [{'name': 'clues.7z', 'url': 'https://api/clues'}, {'name': 'release.json', 'url': 'https://api/meta'}],
                   '_metadata_tag': 'newtag'}
        downloads, imports, backtracks, exports, publishes, noops = [], [], [], [], [], []
        with patch.object(pipeline, 'run', lambda *a, **k: None):
            self.run_pipeline(release, downloads, imports, backtracks, exports, publishes, noops)
        self.assertEqual(len(backtracks), 1)
        self.assertEqual(backtracks[0], 'server')
        self.assertEqual(publishes, [])
        self.assertEqual(noops, [])
        self.assertFalse((self.jobdir / 'release.json').exists())
        self.assertFalse((self.jobdir / 'publish_receipt.json').exists())


if __name__ == '__main__': unittest.main()
