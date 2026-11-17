"""Read-only backend history comparison through an isolated test gateway."""
import asyncio
import copy
import json
import os
from pathlib import Path
import time

import aiohttp
from aiohttp import web
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

from gateway import Config, GATEWAY_KEY, allowed_email, create_app


async def main():
    email = os.environ['TEAM_SMOKE_EMAIL'].lower()
    config = Config('history-smoke', 'history-smoke', 'https://workspace.example.com',
                    allowed_emails=frozenset({email}))
    if not allowed_email(email, config):
        raise ValueError('TEAM_SMOKE_EMAIL must be a valid email')
    app = create_app(config)
    gateway = app[GATEWAY_KEY]
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    gateway.keys = {'history-smoke': private.public_key()}
    gateway.keys_until = time.monotonic() + 600
    now = int(time.time())
    token = jwt.encode({'iss': config.issuer, 'aud': config.audience, 'iat': now - 1,
                        'exp': now + 300, 'email': email}, private,
                       algorithm='RS256', headers={'kid': 'history-smoke'})
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, '127.0.0.1', 18190).start()
    try:
        async with aiohttp.ClientSession() as session:
            async def get(base, path, headers=None):
                async with session.get(base + path, headers=headers) as response:
                    assert response.status == 200, await response.text()
                    return await response.json()
            upstream = 'http://127.0.0.1:8188'
            proxy = 'http://127.0.0.1:18190'
            headers = {'Cf-Access-Jwt-Assertion': token}
            users = await get(upstream, '/users')
            matches = [key for key, name in users['users'].items() if name == email]
            assert len(matches) == 1, 'Existing test profile required; no provisioning allowed'
            gateway.users[email] = matches[0]
            queue = await get(upstream, '/queue')
            assert not queue['queue_running'] and not queue['queue_pending'], 'Idle backend required'
            before = await get(upstream, '/history')
            raw = await get(upstream, '/api/jobs?limit=200')
            filtered = await get(proxy, '/api/jobs?limit=200', headers)
            assert filtered['pagination'] == raw['pagination']
            assert [job['id'] for job in filtered['jobs']] == [job['id'] for job in raw['jobs']]
            removed = 0
            replaced = 0
            for original, actual in zip(raw['jobs'], filtered['jobs']):
                expected = copy.deepcopy(original)
                preview = expected.get('preview_output')
                if preview and preview.get('mediaType') in ['images', 'a_images', 'b_images']:
                    path = Path(preview['type']) / preview.get('subfolder', '') / preview['filename']
                    if not path.exists():
                        expected.pop('preview_output')
                        raw_detail = await get(upstream, '/api/jobs/' + original['id'])
                        for node_id, outputs in raw_detail.get('outputs', {}).items():
                            for kind, images in outputs.items():
                                if kind not in ['images', 'a_images', 'b_images']:
                                    continue
                                for image in images:
                                    candidate = Path(image['type']) / image.get('subfolder', '') / image['filename']
                                    if candidate.is_file() and 'preview_output' not in expected:
                                        expected['preview_output'] = image | {'nodeId': node_id, 'mediaType': kind}
                        if 'preview_output' in expected:
                            replaced += 1
                        else:
                            removed += 1
                assert actual == expected, {'actual': actual, 'expected': expected}
                detail = await get(proxy, '/api/jobs/' + original['id'], headers)
                assert detail['id'] == original['id']
            history = await get(proxy, '/history', headers)
            assert set(history) == set(before)
            for key in before:
                assert {k: v for k, v in history[key].items() if k != 'outputs'} == {
                    k: v for k, v in before[key].items() if k != 'outputs'}
            assert await get(upstream, '/history') == before, 'Backend history changed'
            print(json.dumps({'jobs_preserved': len(filtered['jobs']), 'missing_only_previews_hidden': removed, 'surviving_previews_selected': replaced,
                              'backend_history_unchanged': True}, indent=2))
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    asyncio.run(main())
