# Team workspace gateway

External adapter for one ComfyUI process and one shared queue. Cloudflare Access handles Google login; this standalone gateway verifies Access JWTs before forwarding requests. No ComfyUI core changes, frontend fork, or new authentication network requests from core. Everything here is an example, not a deployment inventory.

## Access and storage

Only trusted teammates should share this workspace. Native profiles separate settings and saved workflows; inputs and supported saver outputs use `users/<email>/` namespaces (unsafe characters are percent-encoded). Queue, history, models, previews, file reads and compute remain shared. Namespaces are **not a privacy boundary**. All admitted users retain queue/history/cancellation controls; no app admin roles are added.

`TEAM_ALLOWED_EMAILS` and `TEAM_ALLOWED_DOMAINS` are comma-separated allowlists, trimmed and lowercased. Exact email or exact domain match admits an identity; a domain does not admit its subdomains. Both lists empty means **deny everyone**. Configure the same intended identities in Cloudflare Access and the gateway. [access-policy.json](access-policy.json) shows reserved example addresses and an unknown identity-provider ID placeholder; replace them before use. Never add Everyone or Bypass policies.

`TEAM_PUBLIC_ORIGIN` is required and must be an HTTPS origin, such as `https://comfy.example.com`. API writes and WebSockets must send that exact `Origin` plus a valid Access JWT assertion. Cloudflare supplies the assertion for browser requests. Caller-supplied profile/authentication headers are stripped. WebSockets close at token expiry; immediate revocation of issued JWTs is not implemented.

## User how-to

1. Open your configured public origin and sign in with an allowed Google account. Coordinate long jobs and cancellations with teammates.
2. Open **Templates**, select a workflow and allow sample inputs to finish downloading/uploading. Verify required models are installed. The service template disables custom nodes, partner API nodes and Assets.
3. LoadImage/LoadImageMask choices include shared input-root images and your own images recursively, excluding symlinks. Reload after externally added files. Old saved widgets may retain `users/<UUID>/...`: reselect the current email-folder input and save again. Submission translation does not rewrite saved widgets or restore deleted files.
4. Use literal relative saver prefixes such as `experiments/portrait`; supported savers route them under `output/users/<email>/`. Absolute paths, `..`, another user's namespace, linked prefixes and unresolved `%...%` tokens are rejected. Reset another user's prefix before reusing shared history.
5. For native **ImageCompare**, enable **Nodes 2.0** in frontend settings. Download results before cleanup; reload history after expiry and reopen templates to fetch missing samples.

Routing covers the explicit native saver allowlist in [gateway.py](gateway.py), not arbitrary custom nodes. `SaveLoRA`'s `prefix`, dataset writers and unknown custom savers are not routed. Native workflows/settings remain under `user/<native-user-id>/`; `user/default` is not automatically copied. `GET /team-workspace` reports your mapping. [migrate_email_folders.py](migrate_email_folders.py) copies legacy UUID file folders without overwriting differing files; stop the gateway and drain the backend queue before migration. Old folders remain for history and links.

The gateway omits confirmed-missing image references/previews from jobs/history responses without deleting jobs, prompts or workflows. Unknown references and failed detail fetches are retained conservatively. `TEAM_INPUT_DIR`, `TEAM_OUTPUT_DIR` and `TEAM_TEMP_DIR` must match backend storage; defaults are this checkout's `input/`, `output/` and `temp/`. Gateway needs local read access.

## Operator setup

1. In [Cloudflare Zero Trust](https://one.dash.cloudflare.com/), select your account and configure a team name. Create a Google OAuth web client with JavaScript origin `https://YOUR_TEAM.cloudflareaccess.com` and redirect URI `https://YOUR_TEAM.cloudflareaccess.com/cdn-cgi/access/callback`. If Google's app is in Testing, register each actual tester email. See [Cloudflare's Google setup](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/google/).
2. Add Google as an identity provider using your client ID and secret. Create a self-hosted Access application for your hostname covering **all paths**. Select only Google, require its identity-provider ID in the Allow policy, and configure explicit email/exact-domain Include rules (OR). Never put secrets in Git or chat.
3. Create a tunnel using your account's normal procedure; keep its credentials outside Git. Copy [workspace.env.example](workspace.env.example) and [cloudflared.example.yml](cloudflared.example.yml) into `~/.config/comfyui-team/` as `workspace.env` and `cloudflared.yml`. Use directory mode 700 and file mode 600. Replace all placeholders, set both layers' matching audience/team values, set the required public origin, and explicitly configure gateway allowlists. Empty allowlists deny everyone.
4. Keep WebSockets enabled and bypass caching for the application hostname. Do not route DNS until Access and both JWT validation layers are configured.

Templates assume a user-service checkout at `%h/src/ComfyUI` (`%h` means the service user's home). Edit installed service paths for another checkout and set device flags for your hardware if necessary; no GPU index is prescribed. Install ComfyUI's dependencies into its own `.venv` and cloudflared separately. Check the tunnel unit's cloudflared binary path. Gateway dependencies use a separate environment:

```bash
cd "$HOME/src/ComfyUI"  # Adjust to your checkout.
uv venv tools/team_workspace/.venv
uv pip install --python tools/team_workspace/.venv/bin/python -r tools/team_workspace/requirements.txt
install -d -m 700 ~/.config/systemd/user
install -m 644 tools/team_workspace/comfyui-team*.service ~/.config/systemd/user/
# Edit installed units/configuration before starting anything.
systemctl --user daemon-reload
cloudflared tunnel --config ~/.config/comfyui-team/cloudflared.yml ingress validate
systemctl --user enable --now comfyui-team-gateway.service
# Missing JWT must return 401; neither loopback port should be publicly reachable.
curl -i http://127.0.0.1:8189/
# New DNS route only; replace placeholders with your own values.
cloudflared tunnel route dns REPLACE_WITH_TUNNEL_UUID comfy.example.com
systemctl --user enable --now comfyui-team-tunnel.service
```

Never tunnel directly to backend port 8188. Both gateway and cloudflared `originRequest.access` validate the application audience. The unauthenticated loopback backend remains reachable by local processes. Configure user lingering separately if services must survive logout; this guide assumes no existing host setup.

## Optional experiment cleanup

[cleanup.py](cleanup.py) previews by default; `--apply` deletes untracked regular input/output/temp files older than 120 minutes. Input basenames declared by the installed template catalog's `io.inputs[].file` survive, including copies in user folders. Outputs get no exemption. Directories and symlinks remain untouched; catalog or Git read failures stop cleanup. Protection matches filenames, not content: unrelated uploads with sample names survive, while collision copies such as `sample (1).png` do not unless cataloged. Missing images are not restored.

To reproduce hourly scheduling, create these two local user units. Set the catalog path to the actual installed template catalog and adjust checkout paths. The service below is deliberately **preview-only**; run and inspect it before adding `--apply` to `ExecStart`. Do not enable destructive cleanup until needed results are backed up outside the expiring trees.

`~/.config/systemd/user/clean-comfy-output.service`:

```ini
[Unit]
Description=Preview expired ComfyUI experiment files

[Service]
Type=oneshot
WorkingDirectory=%h/src/ComfyUI
ExecStart=%h/src/ComfyUI/tools/team_workspace/.venv/bin/python tools/team_workspace/cleanup.py --root %h/src/ComfyUI --catalog /path/to/comfyui_workflow_templates_json/templates/index.json
UMask=0077
```

`~/.config/systemd/user/clean-comfy-output.timer`:

```ini
[Unit]
Description=Check expired ComfyUI experiment files hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

After editing those units, run `systemctl --user daemon-reload`, then `systemctl --user start clean-comfy-output.service` and inspect `journalctl --user -u clean-comfy-output.service`. Enable scheduling with `systemctl --user enable --now clean-comfy-output.timer` only after reviewing the preview and choosing whether to enable deletion. Preview again after catalog/policy changes.

## Validation and maintenance

```bash
uv pip install --python tools/team_workspace/.venv/bin/python pytest pytest-asyncio playwright
tools/team_workspace/.venv/bin/python -m pytest tools/team_workspace/test_gateway.py tools/team_workspace/test_cleanup.py -q -o asyncio_default_fixture_loop_scope=function
tools/team_workspace/.venv/bin/python -m playwright install chromium
# Supply two distinct test emails locally; do not commit identities or artifacts.
export TEAM_SMOKE_EMAIL=alice@example.com
export TEAM_SMOKE_OTHER_EMAIL=bob@example.com
tools/team_workspace/.venv/bin/python tools/team_workspace/smoke_test.py
```

Smoke tests require explicit local identities and allow only those identities in their test gateway. The loopback smoke creates synthetic images/workflows for two profiles, renders EmptyImage → SaveImage, checks shared history and opens WebSockets; it leaves test data behind. Its HTTP-origin override and in-memory JWT key are test-only. [history_smoke.py](history_smoke.py) requires `TEAM_SMOKE_EMAIL` for an existing native profile. Neither script proves Google/Access login or real template behavior.

For acceptance, use separate browser profiles for two allowed accounts and one disallowed account. Verify login denial, uploads, saved workflow separation, two output namespaces, shared queue/history, missing JWT rejection and WebSocket expiry. Exercise actual installed templates with available models and native ImageCompare; do not infer success from a healthy service or synthetic smoke.

Before authentication changes, stop public entry with `systemctl --user stop comfyui-team-tunnel.service`. Update **both** the Access policy and local gateway allowlists, test, restart the gateway and reopen the tunnel. Account removal must consider issued-token expiry and Access session revocation. Before upgrades, drain the queue and back up profiles/results; rerun tests and template acceptance before restoring public access. Inspect services with `systemctl --user status` and logs with `journalctl --user -u <service>`.

To uninstall local services, disable/stop the three workspace services and any cleanup timer. Preserve user data and credentials unless deliberately decommissioning them. Keep OAuth secrets, tunnel credentials, JWTs, local configuration, smoke results/screenshots and virtual environments outside commits.
