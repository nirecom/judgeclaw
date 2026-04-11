# JudgeClaw

Docker Compose deployment of [OpenClaw](https://github.com/openclaw/openclaw) with a custom security layer that compensates for Docker's weaker isolation compared to VM-based sandboxes.

## Design Principles

- **Agent cannot reach external networks** — internal network only
- **All outbound traffic goes through Bridge/Judge** — Agent cannot reach LiteLLM or the internet directly
- **Bridge/Judge inspects all traffic** with PII regex + Judge LLM (fail-closed)
- **Judge LLM uses a different model** from the Agent LLM — bias isolation
- **Restart-resilient** — `restart: unless-stopped` + Docker Desktop auto-start

## Architecture

```mermaid
graph TD
    browser["Browser / Cloudflare"] -->|":18789 WS"| ingress

    subgraph both["int + ext"]
        ingress["openclaw-ingress (nginx)<br/>:18789"]
        bridge["openclaw-bridge (Judge Filter)<br/>:8080"]
        sniproxy["openclaw-sniproxy (nginx stream)<br/>:443 SNI whitelist"]
        dns["openclaw-dns (dnsmasq)<br/>DNS whitelist"]
    end

    subgraph internal["openclaw-internal"]
        subgraph agent_ns["agent network namespace"]
            agent["openclaw-agent"]
            egress["openclaw-egress<br/>(iptables DNAT + default route)"]
        end
    end

    subgraph external["openclaw-external"]
        litellm["openclaw-litellm<br/>:4000 / :4100 debug"]
    end

    sandbox["openclaw-sandbox<br/>network: none (stub)"]

    ingress -->|"WS proxy"| agent
    agent -->|"outbound LLM"| bridge
    agent -.->|"DNS"| dns
    agent -->|"outbound"| egress
    egress -->|"DNAT :443"| sniproxy
    bridge -->|"LLM API"| litellm
    sniproxy -->|"whitelist only"| internet["Internet"]
    litellm --> llamaswap["llama-swap :18080"]

    style internal fill:#1a3a4a,stroke:#2196F3,color:#fff
    style external fill:#3a2a1a,stroke:#FF9800,color:#fff
    style both fill:#2a1a3a,stroke:#9C27B0,color:#fff
    style agent_ns fill:#0d2530,stroke:#1976D2,color:#fff,stroke-dasharray: 5 5
    style sandbox fill:#333,stroke:#666,color:#fff
```

## Prerequisites

- Docker (with Docker Compose)
- An OpenAI-compatible LLM server (configurable via `LLAMA_SERVER_URL` in `.env`, default: `http://host.docker.internal:18080/v1`)

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
| `LLAMA_SERVER_URL` | LLM server URL for Agent model |
| `REASONER_LOCAL_MODEL` | Agent model ID |
| `JUDGE_LOCAL_MODEL` | Judge model ID (via LiteLLM) |
| `PORTABLE_SERVER_URL` | Judge direct fallback URL (skips LiteLLM) |
| `JUDGE_PORTABLE_MODEL` | Judge model ID for direct fallback |
| `BRAVE_API_KEY` | Brave Search API key (web search tool) |

Add domains to `config/whitelist.txt` to expand the SNI/DNS whitelist.

