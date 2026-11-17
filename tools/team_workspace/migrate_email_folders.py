"""One-time local copy of UUID input/output/temp folders; originals stay intact.

Stop gateway and drain backend queue before running. Supply backend checkout path.
Uses native user/users.json identity mapping and default checkout directories only.
Re-runs verify existing copies. Interrupted partial copies fail as conflicts;
inspect and remove only that incomplete destination before retrying.
"""
import hashlib
import json
from pathlib import Path
import shutil
import sys
from urllib.parse import quote


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').digest()


def migrate(root):
    users = json.loads((root / 'user/users.json').read_text())
    count = 0
    for user_id, email in users.items():
        if '@' not in email:
            continue
        component = quote(email.lower(), safe='@._-+')
        if len(component.encode()) > 255 or '/' in user_id or user_id in {'.', '..'}:
            raise ValueError('Invalid user folder mapping')
        for kind in ['input', 'output', 'temp']:
            parent = root / kind / 'users'
            source, destination = parent / user_id, parent / component
            if not source.exists():
                continue
            for ancestor in [root / kind, parent, source, destination]:
                if ancestor.is_symlink():
                    raise ValueError(f'Symlink not supported: {ancestor}')
            for path in sorted(source.rglob('*')):
                if path.is_symlink():
                    raise ValueError(f'Symlink not supported: {path}')
                target = destination / path.relative_to(source)
                if target.is_symlink():
                    raise ValueError(f'Symlink not supported: {target}')
                if path.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                elif path.is_file():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if not target.exists():
                        with path.open('rb') as src, target.open('xb') as dst:
                            shutil.copyfileobj(src, dst)
                        shutil.copystat(path, target)
                    if digest(path) != digest(target):
                        raise ValueError(f'Conflicting copy: {target}')
                    count += 1
            print(f'{source} -> {destination}')
    print(f'Verified {count} copied files; originals retained')


if __name__ == '__main__':
    migrate(Path(sys.argv[1]).resolve())
