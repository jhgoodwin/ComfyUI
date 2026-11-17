import json
import os
import subprocess

import pytest

from cleanup import cleanup


def test_retention(tmp_path):
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    catalog = tmp_path / 'catalog.json'
    catalog.write_text(json.dumps([{'templates': [{'io': {'inputs': [{'file': 'sample.png'}]}}]}]))
    names = ['input/users/alice@example.com/sample.png', 'input/users/alice@example.com/experiment.png',
             'output/users/alice@example.com/sample.png', 'input/tracked.png', 'input/recent.png']
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'image')
        os.utime(path, (1, 1))
    os.utime(tmp_path / 'input/recent.png', (10000, 10000))
    subprocess.run(['git', '-C', str(tmp_path), 'add', 'input/tracked.png'], check=True)
    (tmp_path / 'input/users/empty@example.org').mkdir()
    (tmp_path / 'input/link.png').symlink_to(tmp_path / 'input/tracked.png')
    expected = {'input/users/alice@example.com/experiment.png', 'output/users/alice@example.com/sample.png'}
    assert set(cleanup(tmp_path, catalog, now=10000)) == expected
    assert all((tmp_path / name).exists() for name in names)
    assert set(cleanup(tmp_path, catalog, now=10000, apply=True)) == expected
    assert (tmp_path / 'input/users/empty@example.org').is_dir()
    assert (tmp_path / 'output/users/alice@example.com').is_dir()
    assert (tmp_path / 'input/users/alice@example.com/sample.png').exists()
    assert (tmp_path / 'input/tracked.png').exists()
    assert (tmp_path / 'input/link.png').is_symlink()


def test_symlink_root_fails_before_deletion(tmp_path):
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    catalog = tmp_path / 'catalog.json'
    catalog.write_text(json.dumps([{'templates': [{'io': {'inputs': [{'file': 'sample.png'}]}}]}]))
    (tmp_path / 'input').mkdir()
    stale = tmp_path / 'input/old.png'
    stale.write_bytes(b'keep on failure')
    os.utime(stale, (1, 1))
    (tmp_path / 'outside').mkdir()
    (tmp_path / 'output').symlink_to(tmp_path / 'outside', target_is_directory=True)
    with pytest.raises(ValueError, match='symlink cleanup root'):
        cleanup(tmp_path, catalog, apply=True, now=10000)
    assert stale.exists()


@pytest.mark.parametrize('bad', [[{'templates': {}}], [{'templates': [{'io': {'inputs': {}}}]}]])
def test_malformed_catalog(tmp_path, bad):
    catalog = tmp_path / 'catalog.json'
    good = {'templates': [{'io': {'inputs': [{'file': 'sample.png'}]}}]}
    catalog.write_text(json.dumps([good] + bad))
    with pytest.raises(ValueError, match='Invalid template'):
        cleanup(tmp_path, catalog, apply=True)


def test_temp_retention(tmp_path):
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    catalog = tmp_path / 'catalog.json'
    catalog.write_text(json.dumps([{'templates': [{'io': {'inputs': [{'file': 'sample.png'}]}}]}]))
    folder = tmp_path / 'temp/users/person'
    folder.mkdir(parents=True)
    for name in ['sample.png', 'recent.png', 'tracked.png']:
        path = folder / name
        path.write_bytes(b'image')
        os.utime(path, (1, 1))
    os.utime(folder / 'recent.png', (10000, 10000))
    subprocess.run(['git', '-C', str(tmp_path), 'add', 'temp/users/person/tracked.png'], check=True)
    (folder / 'link.png').symlink_to(folder / 'tracked.png')
    assert cleanup(tmp_path, catalog, now=10000) == ['temp/users/person/sample.png']
    assert (folder / 'sample.png').exists()
    assert cleanup(tmp_path, catalog, now=10000, apply=True) == ['temp/users/person/sample.png']
    assert folder.is_dir()
    assert (folder / 'recent.png').exists()
    assert (folder / 'tracked.png').exists()
    assert (folder / 'link.png').is_symlink()
    assert not (folder / 'sample.png').exists()


def test_bad_catalog_fails_closed(tmp_path):
    catalog = tmp_path / 'catalog.json'
    catalog.write_text('[]')
    with pytest.raises(ValueError, match='no sample inputs'):
        cleanup(tmp_path, catalog, apply=True)
