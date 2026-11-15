import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import traceback
from release import compress, publish, cleanup_payload, check_publish_access, previous_release, download, release_notes


def run(args, **kwargs):
    print('+', ' '.join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def sha256(path):
    with path.open('rb') as f:
        digest = hashlib.sha256()
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
        return digest.hexdigest()


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2))
    temporary.replace(path)


def s2gdu_binary(root):
    return root / 'tools/s2gdu/S2GDU'


def s2gdu_cores():
    value = int(os.environ.get('S2G_CORES', '4'))
    if not 1 <= value <= 64:
        raise RuntimeError('S2G_CORES must be between 1 and 64')
    return value


def resolve_dumps_tag(root, cache, requested):
    args = [s2gdu_binary(root), 'fetch', '--tag', requested or 'latest', '--cache', cache]
    print('+', ' '.join(map(str, args)), flush=True)
    result = subprocess.run(list(map(str, args)), check=True, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, text=True)
    sys.stdout.write(result.stdout)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    match = re.fullmatch(r'tag=(.+)', lines[-1]) if lines else None
    if not match:
        raise RuntimeError('S2GDU fetch did not report a resolved tag')
    return match[1]


def run_container(root, job, jobdir, command_args):
    cores = s2gdu_cores()
    unique = hashlib.sha256(json.dumps(command_args).encode()).hexdigest()[:16]
    state = jobdir / 'ida-state' / unique
    shutil.copytree(root / 'state/linux', state, dirs_exist_ok=True)
    memory = os.environ.get('S2G_ANALYSIS_MEMORY', '16g')
    command = ['docker', 'run', '--rm', '--init', '--name', f"s2gdu-{job['Id']}-{unique}",
               '--label', 's2gdu.job=' + job['Id'], '--network', 'none',
               '--cpus', str(cores), '--memory', memory, '--pids-limit', '512',
               '-v', f'{root}:{root}', '-v', f'{root}/ida/linux:/ida:ro', '-v', f'{state}:/root/.idapro',
               's2gdu-linux:local'] + command_args + ['--ida-path', '/ida', '--cores', str(cores)]
    run(command, stdin=subprocess.DEVNULL)


def run_import(root, job, jobdir, input_dir, seed_file, clues_dir, binary_regex):
    args = ['import', '--input', str(input_dir), '--seed', str(seed_file), '--out', str(clues_dir)]
    if binary_regex:
        args.append(binary_regex)
    run_container(root, job, jobdir, args)


def run_backtrack(root, job, jobdir, input_dir, previous_clues_dir, clues_dir, binary_regex):
    args = ['backtrack', '--input', str(input_dir), '--clues', str(previous_clues_dir), '--out', str(clues_dir)]
    if binary_regex:
        args.append(binary_regex)
    run_container(root, job, jobdir, args)


def run_export(root, clues_dir, out_dir):
    run([s2gdu_binary(root), 'export', '--clues', clues_dir, '--out', out_dir], stdin=subprocess.DEVNULL)


def collect_reports(clues_dir):
    reports = {}
    for path in sorted(clues_dir.glob('*.report.json')):
        reports[path.name[:-len('.report.json')]] = json.loads(path.read_text())
    return reports


def write_noop_receipt(jobdir, release):
    receipt = {'url': release['html_url'], 'tag': release['tag_name'], 'id': release['id'], 'noop': True,
               'assets': [{'name': a['name'], 'url': a['browser_download_url'], 'bytes': a['size']}
                          for a in release['assets']]}
    atomic_json(jobdir / 'publish_receipt.json', receipt)


def pipeline(root, jobfile):
    job = json.loads(jobfile.read_text())
    request = job['Request']
    jobdir = jobfile.parent
    publish_release = request.get('PublishRelease', True)
    if publish_release:
        check_publish_access()
    cache = root / 'cache'
    cache.mkdir(parents=True, exist_ok=True)
    tag = resolve_dumps_tag(root, cache, request.get('DumpsTag'))
    release = previous_release('gd-' + tag, 'clues.7z')
    baseline_metadata = None
    if release is not None:
        metadata_asset = next((a for a in release['assets'] if a['name'] == 'release.json'), None)
        if metadata_asset is None:
            raise RuntimeError(f"Previous release {release['tag_name']} is missing release.json")
        metadata_path = jobdir / 'baseline-release.json'
        download(metadata_asset['url'], metadata_path)
        baseline_metadata = json.loads(metadata_path.read_text())
        metadata_path.unlink()
    if publish_release and baseline_metadata is not None and baseline_metadata.get('dumpsTag') == tag:
        write_noop_receipt(jobdir, release)
        return
    clues_dir = jobdir / 'clues'
    if clues_dir.exists():
        shutil.rmtree(clues_dir)
    clues_dir.mkdir()
    input_dir = cache / tag
    baseline_tag = baseline_metadata.get('dumpsTag') if baseline_metadata else None
    if release is None:
        seed_dir = Path(os.environ.get('S2G_SEED_DIR', str(root / 'seed')))
        if not any((seed_dir / name).is_file() for name in ('signatures.jsonc', 'offsets.jsonc')):
            raise RuntimeError('No signatures.jsonc or offsets.jsonc found in ' + str(seed_dir))
        run_import(root, job, jobdir, input_dir, seed_dir, clues_dir, request.get('BinaryRegex'))
    else:
        clues_asset = next(a for a in release['assets'] if a['name'] == 'clues.7z')
        clues_archive = jobdir / 'baseline-clues.7z'
        download(clues_asset['url'], clues_archive)
        previous_clues = jobdir / 'baseline-clues'
        if previous_clues.exists():
            shutil.rmtree(previous_clues)
        executable = shutil.which('7zz') or shutil.which('7z')
        run([executable, 'x', clues_archive, '-o' + str(previous_clues), '-y'], stdout=subprocess.DEVNULL)
        clues_archive.unlink()
        run_backtrack(root, job, jobdir, input_dir, previous_clues, clues_dir, request.get('BinaryRegex'))
    gamedata_dir = jobdir / 'gamedata'
    run_export(root, clues_dir, gamedata_dir)
    if publish_release:
        reports = collect_reports(clues_dir)
        clues_archive_out = jobdir / 'clues.7z'
        members = sorted(clues_dir.glob('*.gdt.pb')) + sorted(clues_dir.glob('*.report.json'))
        compress(clues_archive_out, members)
        metadata_file = jobdir / 'release.json'
        atomic_json(metadata_file, {'dumpsTag': tag, 'baselineDumpsTag': baseline_tag,
                                     's2gduSha256': sha256(s2gdu_binary(root)), 'reports': reports})
        notes = release_notes(reports, tag, baseline_tag)
        receipt = publish(jobdir, 'gd-' + tag, 'GameData ' + tag,
                           [clues_archive_out, gamedata_dir / 'signatures.jsonc', gamedata_dir / 'offsets.jsonc',
                            metadata_file], notes)
        atomic_json(jobdir / 'publish_receipt.json', receipt)
        cleanup_payload(jobdir)


if __name__ == '__main__':
    root, jobfile = map(Path, sys.argv[1:])
    with (jobfile.parent / 'pipeline.log').open('a', buffering=1) as log:
        os.dup2(log.fileno(), 1)
        os.dup2(log.fileno(), 2)
        try:
            pipeline(root, jobfile)
        except Exception:
            traceback.print_exc()
            sys.exit(1)
