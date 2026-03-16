# Phantom

```
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
```

**LLM Red Teaming & Jailbreak Testing Platform**

Phantom is a comprehensive security testing framework for evaluating the robustness of Large Language Models against adversarial attacks, prompt injection, and jailbreak techniques. It provides structured campaigns, reproducible results, and actionable reports aligned with the OWASP LLM Top 10.

---

## Features

- **Attack Library** — Curated collection of prompt injection, jailbreak, and adversarial attack patterns with version-tracked payloads.
- **Campaign Management** — Organize tests into campaigns with configurable targets, attack sets, and success criteria.
- **OWASP LLM Top 10 Coverage** — Every attack is mapped to OWASP LLM risk categories for compliance-ready reporting.
- **Multi-Target Support** — Test against OpenAI, Anthropic, and any custom API endpoint simultaneously.
- **Mutation Engine** — Automatically generate payload variants through encoding, rephrasing, and obfuscation strategies.
- **Rich CLI** — Interactive terminal interface with progress bars, colored output, and real-time result streaming.
- **Web Dashboard** — Flask-based UI for campaign visualization, result exploration, and report generation.

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/phantom.git
cd phantom

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your API keys

# Run your first scan
python -m phantom scan --target openai --attack-set basic
```

### Docker

```bash
docker-compose up -d
```

## CLI Usage

### Scan a Target

Run a single attack set against a target model:

```bash
# Quick scan with default attacks
phantom scan --target openai --model gpt-4

# Scan a custom endpoint
phantom scan --target-url http://localhost:8080/v1/chat --attack-set injection

# Scan with mutation engine enabled
phantom scan --target anthropic --model claude-3 --mutate --rounds 5
```

### Manage Campaigns

Organize multiple scans into a campaign:

```bash
# Create a new campaign
phantom campaign create --name "Q1 Audit" --targets openai,anthropic

# Run a campaign
phantom campaign run --id camp_abc123

# List campaigns and their status
phantom campaign list
```

### Generate Reports

```bash
# Generate an HTML report for a campaign
phantom report --campaign camp_abc123 --format html

# Export results as JSON
phantom report --campaign camp_abc123 --format json

# Generate OWASP LLM Top 10 compliance summary
phantom report --campaign camp_abc123 --format owasp
```

## Architecture Overview

```
phantom/
├── core/             # Engine, mutation logic, result processing
├── attacks/          # Attack definitions and payload templates
├── campaigns/        # Campaign orchestration and scheduling
├── targets/          # Target adapters (OpenAI, Anthropic, custom)
├── backend/          # Flask API and web dashboard
├── ui/               # Frontend assets for the dashboard
└── tests/            # Test suite
```

**Flow:**

1. **Attacks** are loaded from the attack library (YAML definitions).
2. The **Mutation Engine** (core) expands base payloads into variants.
3. **Campaigns** orchestrate delivery of attacks to one or more **Targets**.
4. Results are stored in SQLite and surfaced via the **CLI** or **Web Dashboard**.
5. **Reports** map findings to OWASP LLM Top 10 categories.

## OWASP LLM Top 10 Mapping

| ID      | Risk Category                        | Phantom Coverage         |
|---------|--------------------------------------|--------------------------|
| LLM01   | Prompt Injection                     | Direct & indirect injection attacks |
| LLM02   | Insecure Output Handling             | Output analysis and payload reflection |
| LLM03   | Training Data Poisoning              | Data extraction probes   |
| LLM04   | Model Denial of Service              | Resource exhaustion payloads |
| LLM05   | Supply Chain Vulnerabilities         | Plugin and tool abuse vectors |
| LLM06   | Sensitive Information Disclosure     | PII and secret extraction attacks |
| LLM07   | Insecure Plugin Design               | Tool-call injection sequences |
| LLM08   | Excessive Agency                     | Autonomy boundary tests  |
| LLM09   | Overreliance                         | Hallucination and confidence probes |
| LLM10   | Model Theft                          | Model extraction and fingerprinting |

## Disclaimer

Phantom is intended **strictly for authorized security testing and research**. Users must obtain explicit permission before testing any LLM system they do not own or operate. The authors assume no liability for misuse. By using this tool you agree to:

- Only test systems you have written authorization to test.
- Comply with all applicable laws and the terms of service of target providers.
- Report vulnerabilities responsibly through appropriate disclosure channels.

**Do not use Phantom for malicious purposes.**

## License

MIT
