#!/usr/bin/env python3
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).parents[1]))
import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / 'clues.7z'
        self.archive.write_bytes(b'archive')
        (self.root / 'release.json').write_text('{}')
        self.draft = True
        self.remote = {}
        self.events = []

    def api(self, method, url, payload=None, path=None):
        self.events.append((method, url))
        if '/assets?' in url:
            return list(self.remote.values())
        if path:
            self.remote[path.name] = dict(name=path.name, state='uploaded', size=path.stat().st_size,
                digest='sha256:' + release.digest(path), browser_download_url='https://github.com/test/' + path.name)
            return self.remote[path.name]
        if method == 'PATCH':
            self.draft = payload['draft']
        return dict(id=123, draft=self.draft, html_url='https://github.com/test/release', upload_url='https://uploads.github.com/test{?name}')

    @unittest.skipUnless(shutil.which('7z') or shutil.which('7zz'), '7-Zip unavailable')
    def test_real_archive_flat_common_and_duplicate_paths(self):
        for name in ('server.gdt.pb', 'engine2.gdt.pb', 'tier0.gdt.pb'):
            (self.root / name).write_bytes((name * 100).encode())
        files = list(self.root.glob('*.gdt.pb'))
        archive = self.root / 'clues.7z'
        release.compress(archive, files)
        output = self.root / 'extracted'
        exe = shutil.which('7zz') or shutil.which('7z')
        subprocess.run([exe, 'x', str(archive), '-o' + str(output)], check=True, stdout=subprocess.DEVNULL)
        self.assertEqual({p.name for p in output.iterdir()}, {p.name for p in files})
        for path in files: self.assertEqual(path.read_bytes(), (output / path.name).read_bytes())
        nested = self.root / 'other'; nested.mkdir()
        duplicate = nested / files[0].name; duplicate.write_bytes(b'different')
        release.compress(self.root / 'duplicate.7z', [files[0], duplicate], base_dir=self.root)
        subprocess.run([exe, 'x', str(self.root / 'duplicate.7z'), '-o' + str(self.root / 'duplicates')],
                       check=True, stdout=subprocess.DEVNULL)
        self.assertEqual((self.root / 'duplicates/other' / duplicate.name).read_bytes(), b'different')

    def test_publish_access_fails_before_analysis(self):
        with patch.object(release, 'api', return_value={'permissions': {'push': False}}):
            with self.assertRaisesRegex(RuntimeError, 'write access'):
                release.check_publish_access()
        with patch.object(release, 'api', return_value={'permissions': {'push': True}}):
            release.check_publish_access()

    def test_publish_verifies_then_cleanup_keeps_metadata(self):
        (self.root / 'clues').mkdir()
        (self.root / 'clues' / 'server.gdt.pb').write_bytes(b'payload')
        with patch.object(release, 'api', self.api):
            receipt = release.publish(self.root, 'gd-abc', 'GameData abc', [self.archive])
        self.assertFalse(self.draft)
        self.assertEqual(len(receipt['assets']), 1)
        with self.assertRaises(FileNotFoundError):
            release.cleanup_payload(self.root)
        (self.root / 'publish_receipt.json').write_text(json.dumps(receipt))
        release.cleanup_payload(self.root)
        self.assertFalse((self.root / 'clues').exists())
        self.assertTrue((self.root / 'release.json').exists())

    def test_failed_digest_never_publishes_or_cleans(self):
        def api(*args, **kwargs):
            result = self.api(*args, **kwargs)
            if isinstance(result, list):
                for asset in result: asset['digest'] = 'sha256:wrong'
            return result
        with patch.object(release, 'api', api), self.assertRaises(RuntimeError):
            release.publish(self.root, 'gd-abc', 'GameData abc', [self.archive])
        self.assertTrue(self.draft)
        self.assertTrue(self.archive.exists())
        self.assertFalse(any(method == 'PATCH' for method, _ in self.events))

    def test_published_release_is_not_overwritten(self):
        self.draft = False
        with patch.object(release, 'api', self.api), self.assertRaises(RuntimeError):
            release.publish(self.root, 'gd-abc', 'GameData abc', [self.archive])
        self.assertFalse(any(method in ('DELETE', 'POST') for method, _ in self.events))

    def test_notes_report_counts_and_baseline(self):
        reports = {'server.dll': {'total': 10, 'survived': 8, 'matched': 1, 'ambiguous': 0, 'none': 1,
                                   'rescued': 0, 'regenerated': 0, 'vtableUpdates': 2}}
        notes = release.release_notes(reports, 'gd-newtag', 'gd-oldtag')
        self.assertIn('Built from dumps `gd-newtag`', notes)
        self.assertIn('compared with `gd-oldtag`', notes)
        self.assertIn('- `server.dll`: total=10', notes)
        clean = release.release_notes({}, 'gd-newtag', None)
        self.assertIn('seeded from scratch', clean)
        self.assertIn('No per-binary reports', clean)
        long_reports = {f'module{i}': {'total': i} for i in range(20000)}
        long = release.release_notes(long_reports, 'gd-newtag', None)
        self.assertLessEqual(len(long), release.MAX_NOTES + 100)
        self.assertTrue(long.endswith('full report.)'))

    def test_notes_become_the_published_body(self):
        bodies = []
        def api(method, url, payload=None, path=None):
            if method == 'PATCH':
                bodies.append(payload.get('body'))
            return self.api(method, url, payload, path)
        with patch.object(release, 'api', api):
            release.publish(self.root, 'gd-abc', 'GameData abc', [self.archive], '## Backtrack report')
        self.assertTrue(bodies[-1].endswith('## Backtrack report'))

    def test_baseline_is_the_newest_other_published_release(self):
        asset = {'name': 'clues.7z', 'url': 'https://api.github.com/assets/1'}
        listing = [dict(tag_name='gd-c', draft=True, assets=[asset]),
                   dict(tag_name='gd-a', draft=False, assets=[asset]),
                   dict(tag_name='gd-d', draft=False, assets=[]),
                   dict(tag_name='gd-e', draft=False, assets=[asset])]
        with patch.object(release, 'api', return_value=listing):
            found = release.previous_release('gd-a', 'clues.7z')
            self.assertEqual(found['tag_name'], 'gd-e')
            self.assertIsNone(release.previous_release('gd-e', 'snapshots.7z'))


if __name__ == '__main__': unittest.main()
