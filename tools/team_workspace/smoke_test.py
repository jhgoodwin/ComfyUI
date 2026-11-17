"""Opt-in real backend test. Creates small images/workflows in supplied test profiles.

Uses a temporary loopback gateway with locally signed test JWTs, never the public
hostname. No model needed. Requires running multi-user ComfyUI on port 8188.
"""
import asyncio
import base64
import json
import os
from pathlib import Path
import time
import uuid
from urllib.parse import quote

import aiohttp
from aiohttp import web
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from playwright.async_api import async_playwright

from gateway import Config, GATEWAY_KEY, allowed_email, create_app


async def main():
    emails = [os.environ['TEAM_SMOKE_EMAIL'].lower(), os.environ['TEAM_SMOKE_OTHER_EMAIL'].lower()]
    config = Config('local-smoke', 'local-smoke-aud', 'https://workspace.example.com',
                    allowed_emails=frozenset(emails))
    if len(set(emails)) != 2 or not all(allowed_email(email, config) for email in emails):
        raise ValueError('TEAM_SMOKE_EMAIL and TEAM_SMOKE_OTHER_EMAIL must be distinct valid emails')
    app = create_app(config)
    gateway = app[GATEWAY_KEY]
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    gateway.keys = {'local-smoke': private.public_key()}
    gateway.keys_until = time.monotonic() + 600
    def token(email):
        now = int(time.time())
        return jwt.encode({'iss': config.issuer, 'aud': config.audience, 'iat': now - 1, 'exp': now + 300, 'email': email}, private, algorithm='RS256', headers={'kid': 'local-smoke'})
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 18189)
    await site.start()
    base = 'http://127.0.0.1:18189'
    # Test-only HTTP origin; production Config deliberately requires HTTPS.
    object.__setattr__(config, 'public_origin', base)
    run = 'team-smoke-' + uuid.uuid4().hex[:8]
    results = {}
    try:
        async with aiohttp.ClientSession() as session:
            for email in emails:
                headers = {'Cf-Access-Jwt-Assertion': token(email), 'Origin': config.public_origin}
                navigation = {'Cf-Access-Jwt-Assertion': token(email), 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document'}
                async with session.get(base + '/', headers=navigation) as r:
                    assert r.status == 200, await r.text()
                    assert '<html' in await r.text()
                async with session.get(base + '/team-workspace', headers=headers) as r:
                    assert r.status == 200, await r.text()
                    identity = await r.json()
                    assert identity['namespace'] == 'users/' + quote(email, safe='@._-+')
                png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=')
                form = aiohttp.FormData()
                form.add_field('image', png, filename=run + '.png', content_type='image/png')
                async with session.post(base + '/api/upload/image', data=form, headers=headers) as r:
                    assert r.status == 200, await r.text()
                    upload = await r.json()
                    assert upload['subfolder'] == identity['namespace']
                async with session.get(base + '/api/object_info/LoadImage', headers=headers) as r:
                    assert r.status == 200, await r.text()
                    choices = (await r.json())['LoadImage']['input']['required']['image'][0]
                    assert upload['subfolder'] + '/' + upload['name'] in choices
                async with session.get(base + '/api/view', params={'filename': upload['subfolder'] + '/' + upload['name'], 'type': 'input'}, headers=headers) as r:
                    assert r.status == 200, await r.text()
                    assert r.headers['Content-Type'].startswith('image/')
                    assert all(not name.startswith('users/') or name.startswith(identity['namespace'] + '/') for name in choices)
                workflow = {'id': run, 'nodes': [], 'links': [], 'version': 0.4, 'extra': {'owner': email}}
                async with session.post(base + '/api/userdata/workflows%2F' + run + '.json', json=workflow, headers=headers) as r:
                    assert r.status == 200, await r.text()
                async with session.get(base + '/api/userdata/workflows%2F' + run + '.json', headers=headers) as r:
                    assert (await r.json())['extra']['owner'] == email
                prompt = {'prompt': {'1': {'class_type': 'EmptyImage', 'inputs': {'width': 32, 'height': 32, 'batch_size': 1, 'color': 255}}, '2': {'class_type': 'SaveImage', 'inputs': {'images': ['1', 0], 'filename_prefix': run}}}}
                async with session.post(base + '/api/prompt', json=prompt, headers=headers) as r:
                    assert r.status == 200, await r.text()
                    prompt_id = (await r.json())['prompt_id']
                async with session.ws_connect(base + '/ws?clientId=' + uuid.uuid4().hex, headers=headers) as ws:
                    msg = await ws.receive(timeout=10)
                    assert msg.type == aiohttp.WSMsgType.TEXT
                async with asyncio.timeout(30):
                    while True:
                        async with session.get(base + '/history/' + prompt_id, headers=headers) as r:
                            history = await r.json()
                        if prompt_id in history:
                            break
                        await asyncio.sleep(0.1)
                item = history[prompt_id]
                assert item['status']['status_str'] == 'success', item
                image = item['outputs']['2']['images'][0]
                assert image['subfolder'] == identity['namespace'], image
                async with session.get(base + '/view', params={k: image[k] for k in ('filename', 'subfolder', 'type')}, headers=headers) as r:
                    assert r.status == 200
                    assert (await r.read()).startswith(b'\x89PNG')
                results[email] = {'identity': identity, 'upload': upload, 'output': image, 'prompt_id': prompt_id}
            # First user sees second user's job: queue/history intentionally shared.
            async with session.get(base + '/history/' + results[emails[1]]['prompt_id'], headers={'Cf-Access-Jwt-Assertion': token(emails[0])}) as r:
                assert results[emails[1]]['prompt_id'] in await r.json()
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(viewport={'width': 1440, 'height': 1000}, extra_http_headers={'Cf-Access-Jwt-Assertion': token(emails[0])})
            page = await context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('console', lambda msg: print('BROWSER', msg.type, msg.text) if msg.type in {'error', 'warning'} else None)
            page.on('response', lambda response: print('HTTP', response.status, response.url) if response.status >= 400 else None)
            page.on('requestfailed', lambda request: print('FAILED', request.url, request.failure))
            await page.goto(base + '/', wait_until='domcontentloaded')
            await page.wait_for_function("document.body.innerText.length > 50", timeout=45000)
            await page.screenshot(path=str(Path(__file__).with_name('workspace-smoke.png')), full_page=True)
            results['browser'] = {'title': await page.title(), 'page_errors': errors, 'text': (await page.locator('body').inner_text())[:2000]}
            await browser.close()
        Path(__file__).with_name('smoke-results.json').write_text(json.dumps(results, indent=2))
        print(json.dumps(results, indent=2))
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    asyncio.run(main())
