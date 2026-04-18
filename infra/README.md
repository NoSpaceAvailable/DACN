# infra/

Operational scripts (not application code).

## `vps-setup.sh`

Idempotent setup script for the VPS hosting Ollama at `157.245.195.74`.

### What it does
- Pins Ollama to listen on `127.0.0.1:11434` only (so it's never directly exposed).
- Installs Caddy as reverse proxy on port 80 with bearer-token auth.
- Configures `ufw` firewall: allows SSH + 80, denies 11434.
- Logs all requests to `/var/log/caddy/ollama-access.log` (JSON, rotated 10 MB × 5).

### Usage

On the VPS as root:

```bash
# Generate a strong token first (KEEP THIS SECRET):
TOKEN=$(openssl rand -hex 32)
echo "$TOKEN"   # save this somewhere safe

# Then run setup:
OLLAMA_TOKEN="$TOKEN" bash vps-setup.sh
```

Optional: restrict SSH source:
```bash
OLLAMA_TOKEN="$TOKEN" ALLOWED_SSH_CIDR="203.0.113.0/24" bash vps-setup.sh
```

### After setup

From your dev machine:

```bash
curl -H "Authorization: Bearer $TOKEN" http://157.245.195.74/api/tags
```

Save in `.env.local` (NOT committed):

```
OLLAMA_BASE_URL=http://157.245.195.74
OLLAMA_TOKEN=<your token>
```

### Limitations
- **No TLS** — bearer token sent over plaintext HTTP. Acceptable for DACN dev (low-stakes, no PII), not for production.
- **Single token** — no per-user audit; rotate by re-running script with new `OLLAMA_TOKEN`.
- **No rate limiting** beyond Caddy default — add `rate_limit` directive if abuse appears in logs.
