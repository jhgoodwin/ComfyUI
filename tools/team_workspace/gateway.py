"""Standalone Cloudflare Access gateway; never import this from ComfyUI.

Run ComfyUI with --multi-user on loopback, then run this file separately.
Required: CF_ACCESS_TEAM (team slug), CF_ACCESS_AUD (Access application audience),
TEAM_PUBLIC_ORIGIN (HTTPS origin). TEAM_ALLOWED_EMAILS and TEAM_ALLOWED_DOMAINS
are comma-separated allowlists; empty lists deny everyone. Optional:
TEAM_BACKEND_URL=http://127.0.0.1:8188, TEAM_GATEWAY_HOST=127.0.0.1,
TEAM_GATEWAY_PORT=8189. Cloudflare Access must use Google's identity provider;
this gateway verifies Access JWTs, not Google ID tokens. Only the fixed team
JWKS endpoint contacts the internet. Never expose the backend around this gate.

Best-effort organization for trusted users, NOT tenant isolation: queue, history,
previews, asset APIs and file reads remain shared. Image dropdowns show root and
own inputs only. Workflows and
settings use native user directories. Upload destinations and the explicit saver
contracts below use users/<email>/ under their native input/output/temp root;
email path components are percent-encoded when needed.
No symlinks may be placed in these managed directories by local operators.
Custom saver paths, SaveLoRA's prefix, dataset folder_name, custom execution
endpoints and dynamically linked saver prefixes are unsupported; custom nodes
are not a security sandbox. Known saver prefixes must be literal relative paths;
percent templates must be expanded by the frontend before submission. Preview nodes
retain native shared temp behavior. Mask original_ref is deliberately unchanged.
Unsafe HTTP requests and WebSockets require the configured Origin, including API
clients. No cookies or identity headers reach ComfyUI. Only one gateway process
should provision users; its lock does not coordinate multiple gateway instances.

Test entry points: Config.from_env, allowed_email, clean_headers, namespace_path,
rewrite_prompt, Gateway.verify_token/provision_user, and create_app. No ComfyUI
imports, private request mutation, filesystem profile edits, or service startup on
import. GET /team-workspace reports the authenticated identity and namespace.
"""

import asyncio
from dataclasses import dataclass
import ipaddress
import json
import math
import mimetypes
import os
from pathlib import Path
import re
import time
from urllib.parse import quote, unquote, urlsplit

import aiohttp
from aiohttp import web
import jwt
from multidict import CIMultiDict
from yarl import URL


SAVERS = frozenset({
    "SaveImage", "SaveImageAdvanced", "SaveLatent", "SaveAnimatedWEBP",
    "SaveAnimatedPNG", "SaveSVGNode", "SaveWEBM", "SaveVideo", "SaveAudio",
    "SaveAudioMP3", "SaveAudioOpus", "SaveAudioAdvanced", "SaveText",
    "SaveConditioning", "CheckpointSave", "CLIPSave", "VAESave", "ModelSave",
    "ImageOnlyCheckpointSave", "LoraSave", "SaveGLB", "Save3DAdvanced",
    "SaveGaussianSplat", "SavePointCloud",
})
HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
})
IDENTITY_HEADERS = frozenset({
    "comfy-user", "authorization", "cookie", "forwarded", "x-real-ip",
    "remote-user", "x-remote-user", "x-user", "x-email", "true-client-ip",
    "origin", "referer", "x-original-url", "x-rewrite-url",
})


@dataclass(frozen=True)
class Config:
    team: str
    audience: str
    public_origin: str
    allowed_emails: frozenset[str] = frozenset()
    allowed_domains: frozenset[str] = frozenset()
    backend_url: str = "http://127.0.0.1:8188"
    host: str = "127.0.0.1"
    port: int = 8189
    input_dir: Path = Path(__file__).resolve().parents[2] / "input"
    output_dir: Path = Path(__file__).resolve().parents[2] / "output"
    temp_dir: Path = Path(__file__).resolve().parents[2] / "temp"

    def __post_init__(self):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", self.team):
            raise ValueError("CF_ACCESS_TEAM must be a Cloudflare team slug")
        if not self.audience or self.audience != self.audience.strip():
            raise ValueError("CF_ACCESS_AUD is required")
        origin = urlsplit(self.public_origin)
        if (origin.scheme != "https" or not origin.hostname or origin.username
                or origin.password or origin.path or origin.query or origin.fragment):
            raise ValueError("TEAM_PUBLIC_ORIGIN must be an HTTPS origin without a trailing slash")
        backend = urlsplit(self.backend_url)
        if (backend.scheme != "http" or backend.username or backend.password
                or backend.path or backend.query or backend.fragment
                or not ipaddress.ip_address(backend.hostname).is_loopback):
            raise ValueError("TEAM_BACKEND_URL must be an HTTP loopback origin")
        if not ipaddress.ip_address(self.host).is_loopback or not 1 <= self.port <= 65535:
            raise ValueError("Gateway must bind a loopback address and valid port")

    @classmethod
    def from_env(cls):
        return cls(
            team=os.environ.get("CF_ACCESS_TEAM", ""),
            audience=os.environ.get("CF_ACCESS_AUD", ""),
            public_origin=os.environ.get("TEAM_PUBLIC_ORIGIN", ""),
            allowed_emails=frozenset(value.strip().lower() for value in os.environ.get("TEAM_ALLOWED_EMAILS", "").split(",") if value.strip()),
            allowed_domains=frozenset(value.strip().lower() for value in os.environ.get("TEAM_ALLOWED_DOMAINS", "").split(",") if value.strip()),
            backend_url=os.environ.get("TEAM_BACKEND_URL", "http://127.0.0.1:8188"),
            host=os.environ.get("TEAM_GATEWAY_HOST", "127.0.0.1"),
            port=int(os.environ.get("TEAM_GATEWAY_PORT", "8189")),
            input_dir=Path(os.environ.get("TEAM_INPUT_DIR", str(cls.input_dir))),
            output_dir=Path(os.environ.get("TEAM_OUTPUT_DIR", str(cls.output_dir))),
            temp_dir=Path(os.environ.get("TEAM_TEMP_DIR", str(cls.temp_dir))),
        )

    @property
    def issuer(self):
        return f"https://{self.team}.cloudflareaccess.com"


def image_choices(root, user_id):
    def is_image(path):
        mime, _ = mimetypes.guess_type(path.name, strict=False)
        return not path.is_symlink() and path.is_file() and mime is not None and mime.startswith("image/")

    if not root.is_dir() or root.is_symlink():
        return []
    choices = [path.name for path in root.iterdir() if is_image(path)]
    own = root / namespace_path("", user_id, allow_empty=True)
    if not (root / "users").is_symlink() and not own.is_symlink():
        for directory, dirs, files in os.walk(own, followlinks=False):
            dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
            for name in files:
                path = Path(directory) / name
                if is_image(path):
                    choices.append(path.relative_to(root).as_posix())
    return sorted(choices)


IMAGE_OUTPUT_KEYS = frozenset({"images", "a_images", "b_images"})


def missing_image(reference, config):
    if not isinstance(reference, dict):
        return False
    filename = reference.get("filename")
    subfolder = reference.get("subfolder", "")
    kind = reference.get("type")
    if not isinstance(kind, str) or kind not in {"input", "output", "temp"}:
        return False
    if (not isinstance(filename, str) or not filename or not isinstance(subfolder, str)
            or filename.endswith(("[input]", "[output]", "[temp]"))
            or any(c in filename for c in "/\\:") or filename in {".", ".."}
            or any(c in subfolder for c in "\\:")
            or any(ord(c) < 32 for c in filename + subfolder)
            or (subfolder and any(part in {"", ".", ".."} for part in subfolder.split("/")))):
        return False
    mime, _ = mimetypes.guess_type(filename, strict=False)
    if mime is None or not mime.startswith("image/"):
        return False
    if "mediaType" in reference and (not isinstance(reference["mediaType"], str)
                                     or reference["mediaType"] not in IMAGE_OUTPUT_KEYS):
        return False
    if "format" in reference and (not isinstance(reference["format"], str)
                                   or not reference["format"].startswith("image/")):
        return False
    root = {"input": config.input_dir, "output": config.output_dir, "temp": config.temp_dir}[kind]
    try:
        root = root.resolve()
        path = (root / subfolder / filename).resolve()
        if not path.is_relative_to(root):
            return False
    except (OSError, RuntimeError, ValueError):
        return False
    try:
        path.stat()
    except FileNotFoundError:
        return True
    except OSError:
        pass
    return False


def filter_missing_images(document, route, config):
    if not isinstance(document, dict):
        return document
    if route == "/jobs":
        records = document.get("jobs", [])
        if not isinstance(records, list):
            return document
    elif route.startswith("/jobs/"):
        records = [document]
    else:
        records = document.values()
    for record in records:
        if not isinstance(record, dict):
            continue
        preview = record.get("preview_output")
        if (isinstance(preview, dict) and isinstance(preview.get("mediaType"), str)
                and preview["mediaType"] in IMAGE_OUTPUT_KEYS and missing_image(preview, config)):
            record.pop("preview_output")
        outputs = record.get("outputs")
        if not isinstance(outputs, dict):
            continue
        for node in outputs.values():
            if not isinstance(node, dict):
                continue
            for key in IMAGE_OUTPUT_KEYS & node.keys():
                if isinstance(node[key], list):
                    node[key] = [item for item in node[key] if not missing_image(item, config)]
        if preview is not None and "preview_output" not in record:
            for node_id, node in outputs.items():
                if not isinstance(node, dict):
                    continue
                for key, items in node.items():
                    if key not in IMAGE_OUTPUT_KEYS or not isinstance(items, list):
                        continue
                    for item in items:
                        if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
                            continue
                        mime, _ = mimetypes.guess_type(item["filename"], strict=False)
                        if mime and mime.startswith("image/") and "preview_output" not in record:
                            record["preview_output"] = {**item, "nodeId": node_id, "mediaType": key}
    return document


def allowed_email(email, config):
    if not isinstance(email, str) or email != email.strip() or email.count("@") != 1:
        return False
    local, domain = email.lower().split("@")
    return bool(local and domain) and not any(c.isspace() for c in email) and (
        email.lower() in config.allowed_emails or domain in config.allowed_domains
    )


def clean_headers(headers, *, response=False):
    blocked = set(HOP_HEADERS)
    for value in headers.getall("Connection", []):
        blocked.update(token.strip().lower() for token in value.split(","))
    result = CIMultiDict()
    for name, value in headers.items():
        lower = name.lower()
        if lower in blocked or lower.startswith("sec-websocket-"):
            continue
        if response:
            if lower in {"set-cookie", "cache-control", "expires", "pragma"} or lower.startswith("access-control-"):
                continue
        elif (lower in IDENTITY_HEADERS or lower in {"host", "sec-fetch-site"}
              or lower.startswith(("cf-", "x-forwarded-", "x-auth-", "x-authenticated-",
                                   "x-user-", "x-email-", "x-goog-", "x-team-"))):
            continue
        result.add(name, value)
    if response:
        result["Cache-Control"] = "no-store"
    return result


def namespace_path(path, user_id, *, allow_empty=False, legacy_user_id=None):
    email = unquote(user_id)
    native_id = re.fullmatch(r"[A-Za-z0-9_-]+", user_id) and not user_id.startswith("__")
    email_id = (email.count("@") == 1 and all(email.split("@"))
                and quote(email, safe="@._-+") == user_id)
    if not (native_id or email_id):
        raise ValueError("Invalid file namespace")
    if len(user_id.encode("utf-8")) > 255:
        raise ValueError("File namespace exceeds 255 bytes")
    if not isinstance(path, str):
        raise ValueError("Dynamic filename_prefix is unsupported; use a literal relative path")
    root = f"users/{user_id}"
    roots = [root]
    if legacy_user_id is not None:
        roots.append(namespace_path("", legacy_user_id, allow_empty=True))
    for own_root in roots:
        if path == own_root:
            if not allow_empty:
                raise ValueError("Saver prefix needs a filename inside the user namespace")
            return root
        if path.startswith(own_root + "/"):
            path = path[len(own_root) + 1:]
            if not path:
                raise ValueError("Path must not contain absolute, empty or traversal components")
            break
    else:
        if path.startswith("users/"):
            raise ValueError("Path belongs to another user namespace")
    if (not path and not allow_empty) or any(ord(c) < 32 for c in path) or any(c in path for c in "\\:%"):
        raise ValueError("Path must be literal and relative, without backslashes, colons or percent tokens")
    if path and any(part in {"", ".", ".."} for part in path.split("/")):
        raise ValueError("Path must not contain absolute, empty or traversal components")
    return root + ("/" + path if path else "")


def rewrite_prompt(body, user_id, legacy_user_id=None):
    if not isinstance(body, dict) or not isinstance(body.get("prompt"), dict):
        raise ValueError("Expected a prompt object")
    for node in body["prompt"].values():
        if not isinstance(node, dict):
            raise ValueError("Expected prompt node objects")
        if node.get("class_type") in SAVERS:
            inputs = node.get("inputs")
            if not isinstance(inputs, dict) or "filename_prefix" not in inputs:
                raise ValueError("Supported savers require an explicit literal filename_prefix")
            inputs["filename_prefix"] = namespace_path(
                inputs["filename_prefix"], user_id, legacy_user_id=legacy_user_id)
        elif legacy_user_id is not None and node.get("class_type") in {"LoadImage", "LoadImageMask"}:
            inputs = node.get("inputs")
            image = inputs.get("image") if isinstance(inputs, dict) else None
            old_root = namespace_path("", legacy_user_id, allow_empty=True)
            if isinstance(image, str) and image.startswith(old_root + "/"):
                inputs["image"] = namespace_path("", user_id, allow_empty=True) + image[len(old_root):]
    return body


class Gateway:
    def __init__(self, config):
        self.config = config
        self.user_lock = asyncio.Lock()
        self.key_lock = asyncio.Lock()
        self.users = {}
        self.keys = {}
        self.keys_until = 0
        self.last_key_fetch = float("-inf")
        self.session = None

    async def lifecycle(self, app):
        async def reject_redirect(session, context, params):
            # ws_connect follows redirects internally; disallow them before retry.
            raise aiohttp.ClientError("Upstream redirect refused")

        trace = aiohttp.TraceConfig()
        trace.on_request_redirect.append(reject_redirect)
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=None, sock_connect=10),
            auto_decompress=False, cookie_jar=aiohttp.DummyCookieJar(),
            trust_env=False, trace_configs=[trace], headers={"Accept-Encoding": "identity"},
        ) as session:
            self.session = session
            yield

    async def verify_token(self, token):
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if header.get("alg") != "RS256" or not isinstance(kid, str) or not kid:
                raise jwt.InvalidTokenError("Invalid signing header")
            async with self.key_lock:
                now = time.monotonic()
                if now >= self.keys_until or kid not in self.keys:
                    if now - self.last_key_fetch < 30:
                        raise jwt.InvalidTokenError("Signing keys unavailable")
                    self.last_key_fetch = now
                    async with self.session.get(
                        self.config.issuer + "/cdn-cgi/access/certs",
                        allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10),
                    ) as response:
                        if response.status != 200:
                            raise web.HTTPServiceUnavailable(text="Signing keys unavailable")
                        document = await response.json()
                    keys = jwt.PyJWKSet.from_dict(document)
                    self.keys = {key.key_id: key.key for key in keys.keys
                                 if key.key_type == "RSA" and key.public_key_use in {None, "sig"}}
                    self.keys_until = now + 300
                key = self.keys.get(kid)
                if key is None:
                    raise jwt.InvalidTokenError("Unknown signing key")
            claims = jwt.decode(
                token, key, algorithms=["RS256"], audience=self.config.audience,
                issuer=self.config.issuer,
                options={"require": ["iss", "aud", "exp", "iat", "email"]},
            )
            for name in ("exp", "iat"):
                value = claims[name]
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                    raise jwt.InvalidTokenError("Invalid token time")
            if claims["exp"] <= max(claims["iat"], time.time()) or claims["iat"] > time.time():
                raise jwt.InvalidTokenError("Invalid token lifetime")
            if not allowed_email(claims["email"], self.config):
                raise web.HTTPForbidden(text="Email not permitted")
            return claims
        except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
            raise web.HTTPUnauthorized(text="Invalid Access token") from exc

    async def provision_user(self, email):
        async with self.user_lock:
            if email in self.users:
                return self.users[email]
            async with self.session.get(self.config.backend_url + "/users", allow_redirects=False) as response:
                if response.status != 200:
                    raise web.HTTPBadGateway(text="Cannot read native users")
                data = await response.json()
            users = data.get("users")
            if not isinstance(users, dict):
                raise web.HTTPServiceUnavailable(text="ComfyUI must run with --multi-user")
            matches = [key for key, name in users.items() if name == email]
            if len(matches) > 1:
                raise web.HTTPServiceUnavailable(text="Duplicate native user mapping")
            if matches:
                user_id = matches[0]
            else:
                async with self.session.post(
                    self.config.backend_url + "/users", json={"username": email}, allow_redirects=False,
                ) as response:
                    if response.status != 200:
                        raise web.HTTPBadGateway(text="Cannot provision native user")
                    user_id = await response.json()
            namespace_path("", user_id, allow_empty=True)
            self.users[email] = user_id
            return user_id

    @web.middleware
    async def authenticate(self, request, handler):
        try:
            origins = request.headers.getall("Origin", [])
            websocket = request.headers.get("Upgrade", "").lower() == "websocket"
            if (origins and origins != [self.config.public_origin]) or (
                not origins and (websocket or request.method not in {"GET", "HEAD", "OPTIONS"})
            ):
                raise web.HTTPForbidden(text="Origin not permitted")
            # Access login redirects arrive as cross-site top-level navigation.
            navigation = (request.method == "GET"
                          and request.headers.get("Sec-Fetch-Mode") == "navigate"
                          and request.headers.get("Sec-Fetch-Dest") == "document")
            if request.headers.get("Sec-Fetch-Site") == "cross-site" and not navigation:
                raise web.HTTPForbidden(text="Cross-site request not permitted")
            tokens = request.headers.getall("Cf-Access-Jwt-Assertion", [])
            if len(tokens) != 1:
                raise web.HTTPUnauthorized(text="Access token required")
            claims = await self.verify_token(tokens[0])
            request["email"] = claims["email"].lower()
            request["file_user"] = quote(request["email"], safe="@._-+")
            namespace_path("", request["file_user"], allow_empty=True)
            request["expires"] = claims["exp"]
            request["user_id"] = await self.provision_user(request["email"])
            return await handler(request)
        except web.HTTPException as exc:
            exc.headers["Cache-Control"] = "no-store"
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return web.Response(status=502, text="Gateway upstream unavailable", headers={"Cache-Control": "no-store"})
        except (ValueError, TypeError, KeyError):
            return web.Response(status=400, text="Malformed request or upstream response", headers={"Cache-Control": "no-store"})

    async def upload_body(self, request):
        if request.content_type != "multipart/form-data":
            raise web.HTTPBadRequest(text="Expected multipart/form-data")
        post = await request.post()
        if any(len(post.getall(key)) != 1 for key in post):
            raise web.HTTPBadRequest(text="Duplicate multipart fields unsupported")
        image = post.get("image")
        if not isinstance(image, web.FileField):
            raise web.HTTPBadRequest(text="Image file required")
        filename = image.filename
        if (not filename or filename in {".", ".."} or any(c in filename for c in "/\\:")
                or any(ord(c) < 32 for c in filename)):
            raise web.HTTPBadRequest(text="Image filename must be a plain basename")
        subfolder = namespace_path(post.get("subfolder", ""), request["file_user"],
                                   allow_empty=True, legacy_user_id=request["user_id"])
        form = aiohttp.FormData(quote_fields=False)
        for key, value in post.items():
            if key == "subfolder":
                continue
            if isinstance(value, web.FileField):
                form.add_field(key, value.file, filename=value.filename, content_type=value.content_type)
            else:
                form.add_field(key, value)
        form.add_field("subfolder", subfolder)
        return form

    async def websocket(self, request, url, headers):
        protocols = tuple(p.strip() for p in request.headers.get("Sec-WebSocket-Protocol", "").split(",") if p.strip())
        async with self.session.ws_connect(url, headers=headers, protocols=protocols, max_msg_size=0) as upstream:
            downstream = web.WebSocketResponse(protocols=[upstream.protocol] if upstream.protocol else (), max_msg_size=0)
            downstream.headers["Cache-Control"] = "no-store"
            await downstream.prepare(request)

            async def relay(source, target):
                async for message in source:
                    if message.type == aiohttp.WSMsgType.TEXT:
                        await target.send_str(message.data)
                    elif message.type == aiohttp.WSMsgType.BINARY:
                        await target.send_bytes(message.data)
                    elif message.type == aiohttp.WSMsgType.ERROR:
                        break

            tasks = [asyncio.create_task(relay(upstream, downstream)),
                     asyncio.create_task(relay(downstream, upstream))]
            try:
                done, pending = await asyncio.wait(
                    tasks, timeout=max(0, request["expires"] - time.time()),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                await downstream.close(code=1000 if done else 1008,
                                       message=b"" if done else b"Access token expired")
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                await upstream.close()
            return downstream

    async def proxy(self, request):
        path = request.path
        if (not path.startswith("/") or path.startswith("//") or "\\" in path
                or any(segment in {".", ".."} for segment in path.split("/"))):
            raise web.HTTPBadRequest(text="Invalid request path")
        route = path[4:] if path.startswith("/api/") else path
        if route == "/users":
            if request.method in {"GET", "HEAD"}:
                return web.json_response({"storage": "server", "migrated": True})
            raise web.HTTPForbidden(text="User management is gateway-owned")
        if route == "/team-workspace":
            if request.method != "GET":
                raise web.HTTPMethodNotAllowed(request.method, ["GET"])
            return web.json_response({"email": request["email"], "user_id": request["user_id"],
                                      "namespace": namespace_path("", request["file_user"], allow_empty=True),
                                      "workflow_directory": f"user/{request['user_id']}/workflows"})
        headers = clean_headers(request.headers)
        headers["comfy-user"] = request["user_id"]
        url = URL(self.config.backend_url + request.raw_path, encoded=True)
        if request.method in {"GET", "HEAD"} and route == "/view" and url.query.get("type") == "input":
            filename = url.query.get("filename", "")
            if "/" in filename and not any(url.query.getall("subfolder", [])):
                if (any(part in {"", ".", ".."} for part in filename.split("/"))
                        or any(char in filename for char in "\\\\:\x00")):
                    raise web.HTTPBadRequest(text="Invalid image path")
                subfolder, filename = filename.rsplit("/", 1)
                url = url.update_query(filename=filename, subfolder=subfolder)
        if request.headers.get("Upgrade", "").lower() == "websocket":
            if route != "/ws" or request.method != "GET":
                raise web.HTTPBadRequest(text="Unsupported WebSocket endpoint")
            return await self.websocket(request, url, headers)
        image_history = re.fullmatch(r"/(?:jobs|history)(?:/[^/]+)?", route) is not None
        if request.method in {"GET", "HEAD"} and (image_history or route in {
            "/object_info", "/object_info/LoadImage", "/object_info/LoadImageMask"
        }):
            headers["Accept-Encoding"] = "identity"
            for name in list(headers):
                if name.lower().startswith("if-") or name.lower() == "range":
                    headers.popall(name, None)
            async with self.session.get(url, headers=headers, allow_redirects=False) as upstream:
                if upstream.status != 200:
                    return web.Response(status=upstream.status, body=await upstream.read(),
                                        headers=clean_headers(upstream.headers, response=True))
                if upstream.headers.get("Content-Encoding", "identity") != "identity":
                    raise web.HTTPBadGateway(text="Compressed rewritten response unsupported")
                info = await upstream.json()
            if image_history:
                jobs = info.get("jobs") if route == "/jobs" and isinstance(info, dict) else None
                previews = [(job, job["preview_output"]) for job in jobs
                            if isinstance(job, dict) and "preview_output" in job] if isinstance(jobs, list) else []
                info = await asyncio.to_thread(filter_missing_images, info, route, self.config)
                for job, preview in previews:
                    if "preview_output" in job or isinstance(job.get("outputs"), dict):
                        continue
                    job_id = job.get("id")
                    if not isinstance(job_id, str) or not job_id or job_id in {".", ".."}:
                        job["preview_output"] = preview
                        continue
                    detail_url = URL(self.config.backend_url + "/api/jobs/" + quote(job_id, safe=""), encoded=True)
                    try:
                        async with self.session.get(detail_url, headers=headers, allow_redirects=False,
                                                    timeout=aiohttp.ClientTimeout(total=10)) as upstream:
                            if upstream.status != 200 or upstream.headers.get("Content-Encoding", "identity") != "identity":
                                job["preview_output"] = preview
                                continue
                            detail = await upstream.json()
                        if not isinstance(detail, dict) or not isinstance(detail.get("outputs"), dict):
                            job["preview_output"] = preview
                            continue
                        detail["preview_output"] = preview
                        detail = await asyncio.to_thread(filter_missing_images, detail, "/jobs/" + job_id, self.config)
                        if "preview_output" in detail:
                            job["preview_output"] = detail["preview_output"]
                    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError):
                        job["preview_output"] = preview
                return web.json_response(info)
            choices = await asyncio.to_thread(image_choices, self.config.input_dir, request["file_user"])
            for node in {"LoadImage", "LoadImageMask"} & info.keys():
                info[node]["input"]["required"]["image"][0] = choices
            return web.json_response(info)
        body = request.content.iter_chunked(64 * 1024) if request.can_read_body else None
        if request.method == "POST" and route in {"/prompt", "/upload/image", "/upload/mask"}:
            if request.headers.get("Content-Encoding", "identity") != "identity":
                raise web.HTTPUnsupportedMediaType(text="Compressed rewritten bodies unsupported")
            headers.popall("Content-Length", None)
            headers.popall("Content-Type", None)
            try:
                if route == "/prompt":
                    body = json.dumps(rewrite_prompt(await request.json(), request["file_user"],
                                                     legacy_user_id=request["user_id"])).encode()
                    headers["Content-Type"] = "application/json"
                else:
                    body = await self.upload_body(request)
            except ValueError as exc:
                raise web.HTTPBadRequest(text=str(exc)) from exc
        async with self.session.request(request.method, url, headers=headers, data=body, allow_redirects=False) as upstream:
            response = web.StreamResponse(status=upstream.status, headers=clean_headers(upstream.headers, response=True))
            await response.prepare(request)
            async for chunk in upstream.content.iter_chunked(64 * 1024):
                await response.write(chunk)
            await response.write_eof()
            return response


GATEWAY_KEY = web.AppKey("gateway", Gateway)


def create_app(config):
    gateway = Gateway(config)
    app = web.Application(middlewares=[gateway.authenticate], client_max_size=512 * 1024 * 1024,
                          handler_args={"auto_decompress": False})
    app[GATEWAY_KEY] = gateway
    app.cleanup_ctx.append(gateway.lifecycle)

    async def no_cache(request, response):
        response.headers["Cache-Control"] = "no-store"
        response.headers.popall("Expires", None)
        response.headers.popall("Pragma", None)

    app.on_response_prepare.append(no_cache)
    app.router.add_route("*", "/{path:.*}", gateway.proxy)
    return app


if __name__ == "__main__":
    config = Config.from_env()
    web.run_app(create_app(config), host=config.host, port=config.port, access_log=None)
