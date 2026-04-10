# Upstream Reference Clones

judgeclaw は `ghcr.io/openclaw/openclaw` image を digest pin で使用しているが、
診断用に OpenClaw の TypeScript ソースを sibling dir に read-only clone している。
判断に迷ったらここを見る。

| Upstream | Local clone | 用途 |
|---|---|---|
| [openclaw/openclaw](https://github.com/openclaw/openclaw) | `c:\LLM\openclaw\` | digest pin 更新時の dist 変更診断、`SsrFPolicy` 等の型定義確認、upstream PR 下調べ |

## 重要

- この clone は **参照専用**。judgeclaw のビルドパイプラインや test からは参照しない
  (bind-mount も COPY もしない)
- 更新は手動 opt-in (`git -C c:/LLM/openclaw pull`)
- `ghcr.io/openclaw/openclaw` の image digest pin とは **別管理**。image は
  `docker-compose.yml` の digest で固定、clone は最新 main を追っても構わない

設計文書: `../../ai-specs/projects/engineering/judgeclaw/architecture.md` の "Upstream reference" 節
