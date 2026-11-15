#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

with tempfile.TemporaryDirectory(prefix='s2gdu-http-') as directory:
    root = Path(directory)
    app = root / 'app'
    shutil.copytree(sys.argv[1], app)
    (app / 'pipeline.py').write_text('''import json, pathlib, sys, time
j = pathlib.Path(sys.argv[2]); data = json.loads(j.read_text())
(j.parent / 'pipeline.log').write_text('test pipeline')
if data['Request']['DumpsTag'] == 'fail-tag': sys.exit(7)
time.sleep(0.25)
a = j.parent / 'artifacts'; a.mkdir(); (a / 'test.gdt.pb.7z').write_bytes(b'test-clues')
if data['Request']['PublishRelease']:
    (j.parent / 'publish_receipt.json').write_text(json.dumps({'url':'https://github.com/Swiftly-Tracker/S2GDU-GameData/releases/tag/test','tag':'gd-test','id':1,'assets':[{'name':'clues.7z','url':'https://github.com/Swiftly-Tracker/S2GDU-GameData/releases/download/test/clues.7z'}]}))
''')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    env = dict(os.environ, S2G_ROOT=str(root), S2G_API_KEY='a' * 32, ASPNETCORE_URLS=base)
    output = (root / 'host.log').open('w')
    def start():
        command = [str(app / 'S2GDU.Automation')] if (app / 'S2GDU.Automation').exists() else ['dotnet', str(app / 'S2GDU.Automation.dll')]
        p = subprocess.Popen(command, env=env, stdout=output, stderr=output)
        for _ in range(100):
            if p.poll() is not None:
                raise RuntimeError((root / 'host.log').read_text())
            try:
                with urllib.request.urlopen(base + '/health', timeout=1): return p
            except OSError: time.sleep(.1)
        p.terminate()
        raise TimeoutError('Service did not start')
    def call(path, data=None, authenticated=True):
        request = urllib.request.Request(base + path, data=json.dumps(data).encode() if data is not None else None,
            headers={'Content-Type': 'application/json', **({'Authorization': 'Bearer ' + 'a' * 32} if authenticated else {})})
        try:
            with urllib.request.urlopen(request, timeout=5) as response: return response.status, response.read()
        except urllib.error.HTTPError as response: return response.code, response.read()
    def wait_job(id):
        for _ in range(100):
            data = json.loads(call('/jobs/' + id)[1])
            if data['state'] in ('failed', 'succeeded'): return data
            time.sleep(.1)
        raise TimeoutError(id)
    request = dict(dumpsTag='v1.2.3', binaryRegex=r'(^|/)test\.dll$', publishRelease=False)
    process = start()
    try:
        assert call('/jobs', authenticated=False)[0] == 401
        assert call('/jobs', {**request, 'dumpsTag': '../etc'})[0] == 400
        assert call('/jobs', {**request, 'dumpsTag': ''})[0] == 400
        assert call('/jobs', {**request, 'binaryRegex': '('})[0] == 400
        assert call('/jobs', {**request, 'binaryRegex': 'x' * 600})[0] == 400
        assert call('/jobs', {**request, 'publishRelease': True})[0] == 400
        code, data = call('/jobs', request)
        assert code == 202 and json.loads(data)['request']['binaryRegex'] == request['binaryRegex']
        id = json.loads(data)['id']
        assert wait_job(id)['state'] == 'succeeded'
        assert call(f'/jobs/{id}/artifacts/0')[1] == b'test-clues'
        assert call(f'/jobs/{id}/artifacts/-1')[0] == 404
        assert call(f'/jobs/{id}/artifacts/1')[0] == 404
        failing = {'dumpsTag': 'fail-tag', 'publishRelease': False}
        failed = json.loads(call('/jobs', failing)[1])['id']
        assert wait_job(failed)['state'] == 'failed'
        assert call(f'/jobs/{failed}/artifacts/0')[0] == 404
        publish = {'dumpsTag': 'v1.2.4'}
        code, data = call('/jobs', publish)
        assert code == 202, data
        published_id = json.loads(data)['id']
        assert json.loads(call('/jobs', publish)[1])['id'] == published_id
        published = wait_job(published_id)
        assert published['state'] == 'succeeded', published
        assert published['artifacts'][0].startswith('https://github.com/')
        assert json.loads(call('/jobs', publish)[1])['id'] == published_id
        retry_request = {'dumpsTag': 'fail-tag'}
        retry_id = json.loads(call('/jobs', retry_request)[1])['id']
        assert wait_job(retry_id)['state'] == 'failed'
        assert json.loads(call('/jobs', retry_request)[1])['id'] == retry_id
        assert wait_job(retry_id)['state'] == 'failed'
        process.terminate(); process.wait(timeout=20)
        stored = json.loads((root / 'jobs' / id / 'job.json').read_text())
        for extra_id, state in [('b' * 32, 'queued'), ('c' * 32, 'running')]:
            path = root / 'jobs' / extra_id; path.mkdir()
            (path / 'job.json').write_text(json.dumps({**stored, 'Id': extra_id, 'State': state, 'Files': None}))
        legacy_path = root / 'jobs' / ('d' * 32); legacy_path.mkdir()
        legacy_request = dict(BinaryRegex='test')
        (legacy_path / 'job.json').write_text(json.dumps({**stored, 'Id': 'd' * 32, 'State': 'queued', 'Request': legacy_request}))
        process = start()
        assert 'format changed' in json.loads(call('/jobs/' + 'd' * 32)[1])['error']
        assert json.loads(call('/jobs/' + id)[1])['state'] == 'succeeded'
        assert wait_job('b' * 32)['state'] == 'succeeded'
        interrupted = json.loads(call('/jobs/' + 'c' * 32)[1])
        assert interrupted['state'] == 'failed' and 'interrupted' in interrupted['error']
        print('PASS HTTP auth, validation, jobs, artifacts, failures, dedupe and restart recovery')
    finally:
        if process.poll() is None: process.terminate(); process.wait(timeout=20)
        output.close()
