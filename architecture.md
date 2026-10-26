src/php_archangel/
├── core/          Evidence-gated pipeline: Evidence → Finding → Verdict (CONFIRMED/PROBABLE/RETRACTED)
├── http/          Session client: keep-alive pinning, worker steering, evidence capture
├── recon/         Tier-1 fingerprinting: headers, easter-egg hash corpus, embedded components, JS analysis
├── verify/        Deterministic oracles: OOM patched-vs-vulnerable divergence, worker-affinity (619)
├── exploit/       Chain-D weapon (embedded poc_109618 logic), --exploit gated
├── ai/            Provider abstraction (OpenRouter default → NVIDIA free default → Anthropic/OpenAI)
├── mcp/           stdio + Streamable HTTP server, dual-gated exploit tool
└── signatures/   Data-driven vuln DB + easter-egg hash corpus + patch-floor knowledge
