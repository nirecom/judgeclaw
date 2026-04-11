# JudgeClaw

Docker Compose deployment of [OpenClaw](https://github.com/openclaw/openclaw) with a custom security layer that compensates for Docker's weaker isolation compared to VM-based sandboxes.

## Security Architecture

- **Judge Filter** (`openclaw-bridge`): FastAPI reverse proxy that intercepts all Agent LLM calls. Blocks requests containing PII (regex patterns + Judge LLM as a second opinion). Fail-closed.
- **Network isolation**: Agent runs on an internal-only network — no direct external access.
- **SNI proxy + DNS whitelist** (`openclaw-sniproxy`, `openclaw-dns`): All outbound HTTPS is filtered by hostname. Default: weather/search only. Add domains to `config/whitelist.txt`.
- **Judge LLM**: Separate model from the Agent model (bias isolation). Runs via llama-swap.

## Prerequisites

- Docker Desktop
- [llama-swap](https://github.com/nirecom/llama-swap) running on `127.0.0.1:18080` (provides Agent and Judge models)
- [openclaw-private](https://github.com/nirecom/openclaw-private) checked out at a sibling path (provides the `workspace/` bind mount)

## Setup

```bash
cp .env.example .env
# Edit .env: set OPENCLAW_GATEWAY_TOKEN, LITELLM_MASTER_KEY, model names, BRAVE_API_KEY
docker compose up -d
```

First-time browser pairing:

```bash
docker exec openclaw-agent openclaw devices list
docker exec openclaw-agent openclaw devices approve <request-id>
```

## Configuration

| Variable | Description |
|----------|-------------|
| `OPENCLAW_GATEWAY_TOKEN` | Gateway auth token (`openssl rand -hex 32`) |
| `OPENCLAW_PORT` | Ingress port (default: 18789) |
| `LITELLM_MASTER_KEY` | LiteLLM internal key |
| `LLAMA_SERVER_URL` | llama-swap URL for Agent model |
| `REASONER_LOCAL_MODEL` | Agent model ID |
| `JUDGE_LOCAL_MODEL` | Judge model ID (via LiteLLM) |
| `PORTABLE_SERVER_URL` | Judge direct fallback URL (skips LiteLLM) |
| `JUDGE_PORTABLE_MODEL` | Judge model ID for direct fallback |
| `BRAVE_API_KEY` | Brave Search API key (web search tool) |

Add domains to `config/whitelist.txt` to expand the SNI/DNS whitelist.

## Docs

Design decisions and operations: [ai-specs/projects/engineering/judgeclaw](https://github.com/nirecom/ai-specs/tree/main/projects/engineering/judgeclaw)
