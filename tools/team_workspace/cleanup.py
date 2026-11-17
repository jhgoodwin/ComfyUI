"""Remove stale experiment files, retaining template inputs and all directories."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import time


def template_names(catalog):
    names = set()
    categories = json.loads(catalog.read_text())
    if not isinstance(categories, list):
        raise ValueError('Invalid template catalog')
    for category in categories:
        if not isinstance(category, dict) or not isinstance(category.get('templates'), list):
            raise ValueError('Invalid template category')
        for template in category['templates']:
            if not isinstance(template, dict):
                raise ValueError('Invalid template entry')
            io = template.get('io', {})
            if not isinstance(io, dict) or not isinstance(io.get('inputs', []), list):
                raise ValueError('Invalid template inputs')
            for item in io.get('inputs', []):
                name = item['file']
                if not isinstance(name, str) or not name or '/' in name or '\\' in name or name in {'.', '..'}:
                    raise ValueError(f'Unsupported template input filename: {name!r}')
                names.add(name)
    if not names:
        raise ValueError('Template catalog contains no sample inputs; refusing cleanup')
    return names


def cleanup(root, catalog, *, apply=False, now=None):
    root = root.resolve(strict=True)
    names = template_names(catalog)
    tracked = set(subprocess.check_output(
        ['git', '-C', str(root), 'ls-files', '-z', '--', 'input/', 'output/', 'temp/']
    ).decode().split('\0'))
    cutoff = (time.time() if now is None else now) - 120 * 60
    candidates = []
    for kind in ['input', 'output', 'temp']:
        folder = root / kind
        if folder.is_symlink():
            raise ValueError(f'Refusing symlink cleanup root: {folder}')
        for directory, dirs, files in os.walk(folder, followlinks=False):
            dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
            for name in files:
                path = Path(directory) / name
                metadata = path.lstat()
                relative = path.relative_to(root).as_posix()
                if (not stat.S_ISREG(metadata.st_mode) or relative in tracked
                        or metadata.st_mtime >= cutoff or (kind == 'input' and name in names)):
                    continue
                candidates.append((path, metadata))
    for path, before in candidates:
        print(('DELETE ' if apply else 'WOULD DELETE ') + str(path))
        if apply:
            # Recheck identity and age: an upload may have replaced the candidate.
            current = path.lstat()
            if (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_size) != (
                    before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size):
                raise RuntimeError(f'File changed during cleanup: {path}')
            if path.resolve().parent != path.parent:
                raise RuntimeError(f'Parent changed during cleanup: {path}')
            path.unlink()
    print(f'{len(candidates)} candidates; {len(names)} protected template names; directories retained')
    return [path.relative_to(root).as_posix() for path, _ in candidates]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    cleanup(args.root, args.catalog, apply=args.apply)
