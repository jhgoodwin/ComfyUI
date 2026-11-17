import asyncio
import copy
import gzip
import json
from pathlib import Path
import threading
from migrate_email_folders import migrate
import time

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from multidict import CIMultiDict
import pytest

import gateway
from gateway import Config, Gateway, allowed_email, clean_headers, create_app, filter_missing_images, image_choices, missing_image, namespace_path, rewrite_prompt


@pytest.fixture
def email_config():
    return Config('test-team', 'aud', 'https://workspace.example.com',
                  allowed_emails=frozenset({'alice@example.com', 'bob@example.com'}),
                  allowed_domains=frozenset({'example.org'}))


def test_allowlist_environment(monkeypatch):
    monkeypatch.setenv('CF_ACCESS_TEAM', 'test-team')
    monkeypatch.setenv('CF_ACCESS_AUD', 'aud')
    monkeypatch.setenv('TEAM_PUBLIC_ORIGIN', 'https://workspace.example.com')
    monkeypatch.delenv('TEAM_ALLOWED_EMAILS', raising=False)
    monkeypatch.delenv('TEAM_ALLOWED_DOMAINS', raising=False)
    config = Config.from_env()
    assert config.allowed_emails == config.allowed_domains == frozenset()
    assert not allowed_email('alice@example.com', config)
    assert not allowed_email('artist@example.org', config)
    monkeypatch.setenv('TEAM_ALLOWED_EMAILS', ' ALICE@EXAMPLE.COM, bob@example.com,, ')
    monkeypatch.setenv('TEAM_ALLOWED_DOMAINS', ' EXAMPLE.ORG, example.net, ,')
    config = Config.from_env()
    assert config.allowed_emails == frozenset({'alice@example.com', 'bob@example.com'})
    assert config.allowed_domains == frozenset({'example.org', 'example.net'})
    assert allowed_email('ALICE@EXAMPLE.COM', config)
    assert allowed_email('artist@EXAMPLE.ORG', config)
    assert not allowed_email('artist@sub.example.org', config)
    monkeypatch.delenv('TEAM_PUBLIC_ORIGIN')
    with pytest.raises(ValueError, match='TEAM_PUBLIC_ORIGIN'):
        Config.from_env()


@pytest.mark.parametrize('email', ['alice@example.com', 'bob@example.com', 'ALICE@EXAMPLE.COM', 'artist@example.org'])
def test_allowed(email, email_config):
    assert allowed_email(email, email_config)


@pytest.mark.parametrize('email', ['alice@evil.com', 'other@example.com', 'x@sub.example.org', 'x@example.org.evil', '@example.org', 'alice@example.com ', ' alice@example.com', 'a b@example.org', 'a\t@example.org', 'a@example.org\n', 'a@@example.org', 'alice@', '', None])
def test_denied(email, email_config):
    assert not allowed_email(email, email_config)


@pytest.mark.parametrize('path', ['../x', '/x', 'x/../y', 'x//y', 'x\\y', 'C:x', '%date:yyyy%', 'users/bob/x', ['5', 0]])
def test_bad_namespace(path):
    with pytest.raises(ValueError):
        namespace_path(path, 'alice')


def test_namespace_root_is_not_a_filename():
    with pytest.raises(ValueError):
        namespace_path('users/alice', 'alice')
    assert namespace_path('users/alice', 'alice', allow_empty=True) == 'users/alice'


def test_rewrite_cache_and_idempotency():
    original = {'prompt': {'1': {'class_type': 'SaveImage', 'inputs': {'filename_prefix': 'renders/demo'}}}}
    alice = rewrite_prompt(copy.deepcopy(original), 'alice')
    bob = rewrite_prompt(copy.deepcopy(original), 'bob')
    assert alice != bob
    assert rewrite_prompt(copy.deepcopy(alice), 'alice') == alice
    assert alice['prompt']['1']['inputs']['filename_prefix'] == 'users/alice/renders/demo'


def test_email_namespace_legacy_prompt():
    component = 'a%2Fb%25tag@example.org'
    prefix = 'users/' + component
    assert namespace_path('demo', component) == prefix + '/demo'
    assert namespace_path(prefix + '/demo', component) == prefix + '/demo'
    with pytest.raises(ValueError):
        namespace_path(prefix + '/%date%', component)
    prompt = {'prompt': {
        '1': {'class_type': 'LoadImage', 'inputs': {'image': 'users/old_id/photo.png [input]'}},
        '2': {'class_type': 'SaveImage', 'inputs': {'filename_prefix': 'users/old_id/render'}},
    }}
    rewritten = rewrite_prompt(prompt, component, 'old_id')
    assert rewritten['prompt']['1']['inputs']['image'] == prefix + '/photo.png [input]'
    assert rewritten['prompt']['2']['inputs']['filename_prefix'] == prefix + '/render'
    assert namespace_path('users/old_id/nested', component, legacy_user_id='old_id') == prefix + '/nested'
    with pytest.raises(ValueError):
        namespace_path('users/someone_else/render', component, legacy_user_id='old_id')


def test_headers():
    headers = CIMultiDict({'Connection': 'X-Secret, keep-alive', 'X-Secret': 'bad', 'Cookie': 'bad', 'Authorization': 'bad', 'comfy-user': 'bob', 'CF-Access-Jwt-Assertion': 'bad', 'X-Forwarded-For': 'bad', 'Sec-Fetch-Site': 'cross-site', 'Accept': 'application/json'})
    assert dict(clean_headers(headers)) == {'Accept': 'application/json'}


def test_email_migration_preserves_originals(tmp_path):
    (tmp_path / 'user').mkdir()
    (tmp_path / 'user/users.json').write_text(json.dumps({'old_id': 'alice@example.com'}))
    original = tmp_path / 'input/users/old_id/nested/a.png'
    original.parent.mkdir(parents=True)
    original.write_bytes(b'original')
    migrate(tmp_path)
    copied = tmp_path / 'input/users/alice@example.com/nested/a.png'
    assert copied.read_bytes() == original.read_bytes()
    assert copied.stat().st_ino != original.stat().st_ino
    migrate(tmp_path)
    copied.write_bytes(b'changed')
    with pytest.raises(ValueError, match='Conflicting copy'):
        migrate(tmp_path)
    assert original.read_bytes() == b'original'


def test_input_directory_symlinks(tmp_path):
    root = tmp_path / 'input'
    root.mkdir()
    (root / 'example.png').touch()
    shared = root / 'shared'
    shared.mkdir()
    (shared / 'hidden.png').touch()
    users = root / 'users'
    users.symlink_to(shared, target_is_directory=True)
    assert image_choices(root, 'alice') == ['example.png']
    users.unlink()
    users.mkdir()
    (users / 'alice').symlink_to(shared, target_is_directory=True)
    assert image_choices(root, 'alice') == ['example.png']
    link = tmp_path / 'linked-input'
    link.symlink_to(root, target_is_directory=True)
    assert image_choices(link, 'alice') == []


@pytest.mark.asyncio
async def test_jwt_validation():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    gate = Gateway(Config('test-team', 'test-aud', 'https://workspace.example.com', allowed_emails=frozenset({'alice@example.com'})))
    gate.keys = {'test': private.public_key()}
    gate.keys_until = time.monotonic() + 600
    now = int(time.time())
    claims = {'iss': gate.config.issuer, 'aud': 'test-aud', 'iat': now - 1, 'exp': now + 60, 'email': 'alice@example.com'}
    def token(changes):
        return jwt.encode(claims | changes, private, algorithm='RS256', headers={'kid': 'test'})
    assert (await gate.verify_token(token({})))['email'] == claims['email']
    gate.config = Config('test-team', 'test-aud', 'https://workspace.example.com')
    with pytest.raises(web.HTTPForbidden):
        await gate.verify_token(token({}))
    gate.config = Config('test-team', 'test-aud', 'https://workspace.example.com',
                         allowed_emails=frozenset({'alice@example.com'}))
    for changes in [{'aud': 'wrong'}, {'iss': 'https://evil.com'}, {'exp': now - 1}, {'iat': now + 120}, {'email': None}]:
        with pytest.raises((web.HTTPUnauthorized, web.HTTPForbidden)):
            await gate.verify_token(token(changes))
    with pytest.raises(web.HTTPForbidden):
        await gate.verify_token(token({'email': 'other@example.com'}))
    with pytest.raises(web.HTTPUnauthorized):
        await gate.verify_token(jwt.encode(claims, 'not-rsa-' * 8, algorithm='HS256', headers={'kid': 'test'}))


@pytest.mark.asyncio
async def test_proxy_routes_uploads_and_websocket(monkeypatch, tmp_path):
    for name in ['example.png', 'users/alice@example.com/nested/alice.png', 'users/bob@example.com/bob.jpg', 'users/alice@example.com/no.txt']:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'fixture')
    (tmp_path / 'users/alice@example.com/leak.png').symlink_to(tmp_path / 'users/bob@example.com/bob.jpg')
    (tmp_path / 'users/alice@example.com/leak-dir').symlink_to(tmp_path / 'users/bob@example.com', target_is_directory=True)
    users = {}
    recorded = []
    async def backend(request):
        path = request.path.removeprefix('/api')
        if path == '/users':
            if request.method == 'GET':
                return web.json_response({'storage': 'server', 'users': users})
            data = await request.json()
            user_id = 'person_' + str(len(users))
            users[user_id] = data['username']
            return web.json_response(user_id)
        if path == '/object_info' or path.startswith('/object_info/'):
            assert request.headers['Accept-Encoding'] == 'identity'
            assert 'If-None-Match' not in request.headers and 'Range' not in request.headers
            if request.query.get('test_error'):
                return web.Response(status=404, text='missing')
            if request.query.get('test_gzip'):
                return web.Response(body=gzip.compress(b'{}'), headers={'Content-Encoding': 'gzip', 'Content-Type': 'application/json'})
            nodes = {'LoadImage': {'input': {'required': {'image': [['example.png'], {'image_upload': True}]}}},
                     'LoadImageMask': {'input': {'required': {'image': [['example.png'], {'image_upload': True}], 'channel': [['red', 'alpha']]}}},
                     'LoadImageOutput': {'input': {'required': {'image': [['output.png']]}}}}
            if path != '/object_info':
                name = path.rsplit('/', 1)[1]
                nodes = {name: nodes[name]}
            return web.json_response(nodes, headers={'ETag': 'stale'})
        if path == '/view':
            return web.json_response(dict(request.query))
        if path == '/ws':
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    await ws.send_bytes(msg.data)
                elif msg.type == aiohttp.WSMsgType.TEXT:
                    await ws.send_str(msg.data)
            return ws
        data = {'user': request.headers.get('comfy-user'), 'cookie': request.headers.get('Cookie'), 'token': request.headers.get('Cf-Access-Jwt-Assertion')}
        if path in {'/prompt', '/echo'}:
            data['body'] = await request.json()
        if path.startswith('/upload/'):
            post = await request.post()
            data['subfolder'] = post['subfolder']
            data['filename'] = post['image'].filename
            data['content'] = post['image'].file.read().decode()
            data['original_ref'] = post.get('original_ref')
        recorded.append(data)
        return web.json_response(data)
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', backend)
    async with TestServer(app) as origin:
        async def verify(self, token):
            if token not in {'alice', 'bob'}:
                raise web.HTTPUnauthorized()
            return {'email': token + '@example.com', 'exp': time.time() + 60}
        monkeypatch.setattr(Gateway, 'verify_token', verify)
        config = Config('test-team', 'aud', 'https://workspace.example.com', backend_url=str(origin.make_url('')).rstrip('/'), input_dir=tmp_path)
        async with TestClient(TestServer(create_app(config))) as client:
            headers = {'Origin': config.public_origin, 'Cf-Access-Jwt-Assertion': 'alice', 'comfy-user': 'spoof', 'Cookie': 'secret'}
            assert (await client.get('/')).status == 401
            navigation = {'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document'}
            assert (await client.get('/', headers=navigation)).status == 401
            authenticated_navigation = navigation | {'Cf-Access-Jwt-Assertion': 'alice'}
            assert (await client.get('/', headers=authenticated_navigation)).status == 200
            assert (await client.get('/', headers=authenticated_navigation | {'Origin': 'https://evil.com'})).status == 403
            assert (await client.get('/api/queue', headers=authenticated_navigation | {'Sec-Fetch-Mode': 'cors'})).status == 403
            assert (await client.get('/', headers=authenticated_navigation | {'Sec-Fetch-Dest': 'iframe'})).status == 403
            assert (await client.post('/prompt', headers=authenticated_navigation | {'Origin': config.public_origin})).status == 403
            assert (await client.post('/prompt', headers=headers | {'Origin': 'https://evil.com'})).status == 403
            for prefix in ['', '/api']:
                response = await client.get(prefix + '/users', headers=headers)
                assert await response.json() == {'storage': 'server', 'migrated': True}
                assert response.headers['Cache-Control'] == 'no-store'
                assert (await client.post(prefix + '/users', json={'username': 'evil'}, headers=headers)).status == 403
                prompt = {'prompt': {'1': {'class_type': 'SaveImage', 'inputs': {'filename_prefix': 'demo'}}}}
                response = await client.post(prefix + '/prompt', json=prompt, headers=headers)
                data = await response.json()
                assert data['body']['prompt']['1']['inputs']['filename_prefix'] == 'users/alice@example.com/demo'
                assert data['user'] == 'person_0'
                assert data['token'] is None and data['cookie'] is None
                for path in ['/upload/image', '/upload/mask']:
                    form = aiohttp.FormData()
                    form.add_field('image', b'image-content', filename='test.png', content_type='image/png')
                    form.add_field('subfolder', 'nested')
                    form.add_field('original_ref', '{"filename":"source.png"}')
                    response = await client.post(prefix + path, data=form, headers=headers)
                    data = await response.json()
                    assert data['subfolder'] == 'users/alice@example.com/nested'
                    assert data['content'] == 'image-content'
                    assert data['original_ref'] == '{"filename":"source.png"}'
            for prefix in ['', '/api']:
                response = await client.get(prefix + '/view', params={'filename': 'users/alice@example.com/nested/a b@c.png', 'type': 'input', 'preview': 'webp;90'}, headers=headers)
                assert await response.json() == {'filename': 'a b@c.png', 'subfolder': 'users/alice@example.com/nested', 'type': 'input', 'preview': 'webp;90'}
                params = [('filename', 'users/a/b.png'), ('type', 'input'), ('subfolder', ''), ('subfolder', 'explicit')]
                response = await client.get(prefix + '/view', params=params, headers=headers)
                assert (await response.json())['filename'] == 'users/a/b.png'
                response = await client.head(prefix + '/view', params={'filename': 'users/a/b.png', 'type': 'input'}, headers=headers)
                assert response.status == 200
                for bad in ['../a.png', '/a.png', 'users//a.png', 'users/../a.png', 'users/evil\\\\a.png']:
                    response = await client.get(prefix + '/view', params={'filename': bad, 'type': 'input'}, headers=headers)
                    assert response.status == 400
            response = await client.get('/object_info?test_gzip=1', headers=headers)
            assert response.status == 502 and response.headers['Cache-Control'] == 'no-store'
            response = await client.get('/object_info?test_error=1', headers=headers)
            assert response.status == 404 and await response.text() == 'missing'
            for prefix in ['', '/api']:
                for suffix in ['', '/LoadImage', '/LoadImageMask']:
                    metadata_headers = headers | {'Accept-Encoding': 'gzip', 'If-None-Match': 'stale', 'Range': 'bytes=0-1'}
                    response = await client.get(prefix + '/object_info' + suffix, headers=metadata_headers)
                    assert response.status == 200 and 'ETag' not in response.headers
                    info = await response.json()
                    for node in {'LoadImage', 'LoadImageMask'} & info.keys():
                        assert info[node]['input']['required']['image'] == [['example.png', 'users/alice@example.com/nested/alice.png'], {'image_upload': True}]
                    if 'LoadImageOutput' in info:
                        assert info['LoadImageOutput']['input']['required']['image'][0] == ['output.png']
                        assert info['LoadImageMask']['input']['required']['channel'] == [['red', 'alpha']]
                    response = await client.head(prefix + '/object_info' + suffix, headers=metadata_headers)
                    assert response.status == 200 and await response.read() == b''
            response = await client.get('/object_info/LoadImage', headers=headers | {'Cf-Access-Jwt-Assertion': 'bob'})
            assert (await response.json())['LoadImage']['input']['required']['image'][0] == ['example.png', 'users/bob@example.com/bob.jpg']
            (tmp_path / 'users/alice@example.com/new.webp').write_bytes(b'new')
            response = await client.get('/object_info/LoadImage', headers=headers)
            assert 'users/alice@example.com/new.webp' in (await response.json())['LoadImage']['input']['required']['image'][0]
            response = await client.post('/echo', data=gzip.compress(b'{"compressed":true}'), headers=headers | {'Content-Encoding': 'gzip', 'Content-Type': 'application/json'})
            assert response.status == 200
            assert (await response.json())['body'] == {'compressed': True}
            responses = await asyncio.gather(*[client.get('/team-workspace', headers=headers | {'Cf-Access-Jwt-Assertion': 'bob'}) for _ in range(5)])
            assert all(r.status == 200 for r in responses)
            assert len(users) == 2
            async with client.ws_connect('/ws?clientId=test', headers=headers) as ws:
                await ws.send_str('hello')
                assert (await ws.receive()).data == 'hello'
                await ws.send_bytes(b'\x00\x01preview')
                assert (await ws.receive()).data == b'\x00\x01preview'



def test_history_directory_config(monkeypatch, tmp_path):
    monkeypatch.setenv('CF_ACCESS_TEAM', 'test-team')
    monkeypatch.setenv('CF_ACCESS_AUD', 'aud')
    monkeypatch.setenv('TEAM_PUBLIC_ORIGIN', 'https://workspace.example.com')
    for kind in ('input', 'output', 'temp'):
        monkeypatch.delenv('TEAM_' + kind.upper() + '_DIR', raising=False)
    config = Config.from_env()
    for kind in ('input', 'output', 'temp'):
        assert getattr(config, kind + '_dir') == Path(gateway.__file__).resolve().parents[2] / kind
        monkeypatch.setenv('TEAM_' + kind.upper() + '_DIR', str(tmp_path / kind))
    config = Config.from_env()
    for kind in ('input', 'output', 'temp'):
        assert getattr(config, kind + '_dir') == tmp_path / kind


def test_missing_image_conservative_paths(monkeypatch, tmp_path):
    config = Config('test-team', 'aud', 'https://workspace.example.com', input_dir=tmp_path, output_dir=tmp_path, temp_dir=tmp_path)
    reference = {'filename': 'missing.png', 'subfolder': '', 'type': 'output'}
    assert missing_image(reference, config)
    (tmp_path / 'present.png').touch()
    (tmp_path / 'directory.png').mkdir()
    (tmp_path / 'escape').symlink_to(tmp_path.parent / 'outside', target_is_directory=True)
    (tmp_path / 'escape.png').symlink_to(tmp_path.parent / 'outside.png')
    retained = [None, 'missing.png', {}, reference | {'filename': 'present.png'},
                reference | {'filename': 'directory.png'}, reference | {'filename': 'escape.png'},
                reference | {'subfolder': 'escape'}, reference | {'type': 'unknown'},
                reference | {'type': []}, reference | {'filename': None},
                reference | {'subfolder': None}, reference | {'mediaType': []},
                reference | {'mediaType': 'video'}, reference | {'format': 'video/webm'},
                reference | {'format': None}]
    for filename in ('../x.png', '/x.png', 'nested/x.png', 'x\\y.png', 'x:foo.png', '.', '..',
                     'bad\x00.png', 'blake3:abc', 'file.txt', 'file.webm', 'unknown.ext',
                     'x.png [input]', 'x.png [output]', 'x.png [temp]'):
        retained.append(reference | {'filename': filename})
    for folder in ('../x', '/x', 'x//y', 'x/../y', 'x/./y', 'x\\y', 'x:y', 'x\x00y'):
        retained.append(reference | {'subfolder': folder})
    assert all(not missing_image(item, config) for item in retained)
    folder = tmp_path / 'users/a%2Fb@example.org'
    folder.mkdir(parents=True)
    (folder / 'present.png').touch()
    assert not missing_image(reference | {'filename': 'present.png', 'subfolder': 'users/a%2Fb@example.org'}, config)
    for document, route in ((None, '/jobs'), ([], '/history'), ({'jobs': {}}, '/jobs'),
                            ({'jobs': [None, {'outputs': []}, {'outputs': {'9': {'images': {}}}}]}, '/jobs'),
                            ({'x': None, 'y': {'outputs': {'9': None}}}, '/history')):
        assert filter_missing_images(copy.deepcopy(document), route, config) == document
    original_stat = Path.stat
    for error in (PermissionError, NotADirectoryError, OSError):
        def fail(path, *args, **kwargs):
            if path.name == 'missing.png':
                raise error('uncertain')
            return original_stat(path, *args, **kwargs)
        monkeypatch.setattr(Path, 'stat', fail)
        assert not missing_image(reference, config)


@pytest.mark.asyncio
async def test_filtered_jobs_and_history_http(monkeypatch, tmp_path):
    roots = {kind + '_dir': tmp_path / kind for kind in ('input', 'output', 'temp')}
    for root in roots.values():
        root.mkdir()
        (root / 'present.png').touch()
    missing = {'filename': 'missing.png', 'subfolder': '', 'type': 'output'}
    present = missing | {'filename': 'present.png'}
    outputs = {'9': {'images': [missing, present, {'custom': 'retain'}],
                     'a_images': [missing | {'type': 'input'}],
                     'b_images': [missing | {'type': 'temp'}],
                     'text': ['keep', missing], 'audio': [missing], 'animated': [True],
                     'metadata': {'images': [missing]}}, 'other': 'unchanged'}
    preview = missing | {'nodeId': '9', 'mediaType': 'images'}
    job = {'id': 'completed', 'status': 'completed', 'outputs_count': 5,
           'previewable_outputs_count': 5, 'preview_output': preview, 'outputs': outputs,
           'workflow_id': 'workflow', 'workflow': {'prompt': {'images': [missing]}, 'extra_data': {'x': 1}},
           'execution_status': {'messages': []}, 'execution_meta': {'9': {}}, 'extra': 'preserved'}
    other_jobs = [{'id': 'pending', 'status': 'pending'}, {'id': 'failed', 'status': 'failed'},
                  {'id': 'text', 'preview_output': {'mediaType': 'text', 'content': 'keep'}},
                  {'id': 'present', 'preview_output': present | {'nodeId': '9', 'mediaType': 'images'}}]
    listing = {'jobs': [job, *other_jobs], 'pagination': {'offset': 10, 'limit': 5, 'total': 44, 'has_more': True}, 'extra': True}
    history = {'completed': {'outputs': outputs, 'prompt': [1, 'completed', {'images': [missing]}, {'workflow': 'keep'}],
                             'status': {'status_str': 'success'}, 'meta': {'9': {}}},
               'empty': {'outputs': {}, 'prompt': ['keep']}}
    expected_job = copy.deepcopy(job)
    expected_job['preview_output'] = present | {'nodeId': '9', 'mediaType': 'images'}
    expected_outputs = expected_job['outputs']
    expected_outputs['9']['images'] = [present, {'custom': 'retain'}]
    expected_outputs['9']['a_images'] = []
    expected_outputs['9']['b_images'] = []
    expected_listing = copy.deepcopy(listing)
    expected_listing['jobs'][0] = expected_job
    expected_history = copy.deepcopy(history)
    expected_history['completed']['outputs'] = expected_outputs
    calls = []
    async def backend(request):
        if request.path == '/users':
            return web.json_response({'users': {'native': 'alice@example.com'}})
        calls.append((request.method, request.path, dict(request.query)))
        assert request.method == 'GET'
        assert request.headers['Accept-Encoding'] == 'identity'
        assert request.headers['comfy-user'] == 'native'
        assert not any(name.lower().startswith('if-') or name.lower() == 'range' for name in request.headers)
        if request.query.get('error'):
            return web.Response(status=404, body=b'not-json', headers={'ETag': 'error-tag'})
        if request.query.get('gzip'):
            return web.Response(body=gzip.compress(b'{}'), headers={'Content-Encoding': 'gzip', 'Content-Type': 'application/json'})
        route = request.path.removeprefix('/api')
        document = listing if route == '/jobs' else job if route.startswith('/jobs/') else history
        return web.json_response(document, headers={'ETag': 'stale', 'Last-Modified': 'old', 'Content-Range': 'stale'})
    async def verify(self, token):
        return {'email': 'alice@example.com', 'exp': time.time() + 60}
    monkeypatch.setattr(Gateway, 'verify_token', verify)
    filter_threads = []
    def track_filter(*args):
        filter_threads.append(threading.get_ident())
        return filter_missing_images(*args)
    monkeypatch.setattr(gateway, 'filter_missing_images', track_filter)
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', backend)
    async with TestServer(app) as origin:
        config = Config('test-team', 'aud', 'https://workspace.example.com', backend_url=str(origin.make_url('')).rstrip('/'), **roots)
        async with TestClient(TestServer(create_app(config))) as client:
            headers = {'Cf-Access-Jwt-Assertion': 'token', 'Accept-Encoding': 'gzip',
                       'If-None-Match': 'stale', 'If-Modified-Since': 'old', 'Range': 'bytes=0-1', 'If-Range': 'old'}
            for prefix in ('', '/api'):
                for route, expected in (('/jobs', expected_listing), ('/jobs/completed', expected_job),
                                        ('/history', expected_history), ('/history/completed', expected_history)):
                    for method in ('GET', 'HEAD'):
                        response = await client.request(method, prefix + route + '?offset=10&limit=5', headers=headers)
                        assert response.status == 200
                        assert response.headers['Cache-Control'] == 'no-store'
                        assert not {'ETag', 'Last-Modified', 'Content-Range', 'Content-Encoding'} & response.headers.keys()
                        if method == 'HEAD':
                            assert await response.read() == b''
                        else:
                            assert await response.json() == expected
                        assert calls[-1] == ('GET', prefix + route, {'offset': '10', 'limit': '5'})
                    response = await client.get(prefix + route + '?error=1', headers=headers)
                    assert response.status == 404 and await response.read() == b'not-json'
                    assert response.headers['ETag'] == 'error-tag'
                    assert response.headers['Cache-Control'] == 'no-store'
                    response = await client.get(prefix + route + '?gzip=1', headers=headers)
                    assert response.status == 502
            assert filter_threads and all(t != threading.get_ident() for t in filter_threads)
            assert listing['jobs'][0]['preview_output'] == preview
            assert outputs['9']['images'][0] == missing


@pytest.mark.asyncio
async def test_jobs_list_fetches_only_missing_preview_details(monkeypatch, tmp_path):
    (tmp_path / 'present.png').touch()
    missing = {'filename': 'missing.png', 'subfolder': '', 'type': 'output', 'mediaType': 'images', 'nodeId': '1'}
    present = missing | {'filename': 'present.png'}
    ids = ['mixed', 'gone', 'failed', 'malformed', 'compressed', 'bad-json', 'a/b?x#y', '..']
    jobs = [{'id': value, 'preview_output': missing, 'outputs_count': 7} for value in ids]
    jobs += [{'id': 'present', 'preview_output': present}, {'id': 'pending', 'status': 'pending'}]
    listing = {'jobs': jobs, 'pagination': {'total': 10, 'offset': 0, 'limit': 10, 'has_more': False}}
    details = []
    async def backend(request):
        if request.path == '/users':
            return web.json_response({'users': {'native': 'alice@example.com'}})
        assert request.method == 'GET'
        assert request.headers['Accept-Encoding'] == 'identity'
        assert request.headers['comfy-user'] == 'native'
        assert 'Range' not in request.headers and 'If-None-Match' not in request.headers
        if request.path == '/api/jobs':
            return web.json_response(listing)
        details.append(request.raw_path)
        assert not request.query
        job_id = request.path.removeprefix('/api/jobs/')
        if job_id == 'failed':
            return web.Response(status=503)
        if job_id == 'malformed':
            return web.json_response({'outputs': []})
        if job_id == 'compressed':
            return web.Response(body=gzip.compress(b'{}'), headers={'Content-Encoding': 'gzip', 'Content-Type': 'application/json'})
        if job_id == 'bad-json':
            return web.Response(text='{', content_type='application/json')
        images = [missing] if job_id == 'gone' else [missing, present]
        return web.json_response({'id': job_id, 'outputs': {'2': {'images': images}}})
    async def verify(self, token):
        return {'email': 'alice@example.com', 'exp': time.time() + 60}
    monkeypatch.setattr(Gateway, 'verify_token', verify)
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', backend)
    async with TestServer(app) as origin:
        config = Config('test-team', 'aud', 'https://workspace.example.com', backend_url=str(origin.make_url('')).rstrip('/'), output_dir=tmp_path)
        async with TestClient(TestServer(create_app(config))) as client:
            response = await client.get('/api/jobs', headers={'Cf-Access-Jwt-Assertion': 'token', 'If-None-Match': 'old', 'Range': 'bytes=0-1'})
            assert response.status == 200
            expected = copy.deepcopy(listing)
            expected['jobs'][0]['preview_output'] = present | {'nodeId': '2'}
            expected['jobs'][1].pop('preview_output')
            expected['jobs'][6]['preview_output'] = present | {'nodeId': '2'}
            assert await response.json() == expected
            assert details == ['/api/jobs/' + value for value in ids[:6]] + ['/api/jobs/a%2Fb%3Fx%23y']
