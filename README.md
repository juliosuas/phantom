<p align="center">

```
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
```

  <strong>LLM Red Teaming & Jailbreak Testing Platform</strong><br>
  <em>Find the cracks before the attackers do.</em>

</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Docker-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010-orange?logo=owasp" alt="OWASP LLM Top 10">
  <img src="https://img.shields.io/badge/targets-OpenAI%20%7C%20Anthropic%20%7C%20Custom-blueviolet" alt="Multi-target">
  <img src="https://img.shields.io/badge/status-active-brightgreen" alt="Status">
</p>

---

## What is Phantom?

Phantom is a comprehensive security testing framework for evaluating the **robustness of Large Language Models** against adversarial attacks, prompt injection, and jailbreak techniques. It provides structured campaigns, reproducible results, and actionable reports aligned with the **OWASP LLM Top 10**.

> **For security teams, AI red teamers, and responsible AI engineers** who need to find vulnerabilities before they're exploited in production.

---

## ✨ Features

- 🗡️ **Attack Library** — Curated collection of prompt injection, jailbreak, and adversarial attack patterns with version-tracked payloads
- 🎯 **Campaign Management** — Organize tests into campaigns with configurable targets, attack sets, and success criteria
- 🛡️ **OWASP LLM Top 10 Coverage** — Every attack mapped to OWASP risk categories for compliance-ready reporting
- 🌐 **Multi-Target Support** — Test OpenAI, Anthropic, and any custom API endpoint simultaneously
- 🧬 **Mutation Engine** — Automatically generate payload variants through encoding, rephrasing, and obfuscation strategies
- 💻 **Rich CLI** — Interactive terminal interface with progress bars, colored output, and real-time result streaming
- 📊 **Web Dashboard** — Flask-based UI for campaign visualization, result exploration, and report generation
- 📄 **Multiple Report Formats** — HTML, JSON, and OWASP compliance summary exports

---

## 🚀 Quick Start

```bash
git clone https://github.com/juliosuas/phantom.git && cd phantom
pip install -r requirements.txt
cp .env.example .env           # Add your API keys
python -m phantom scan --target openai --attack-set basic
```

> **Docker:** `docker-compose up -d`

---

## 📸 Screenshots

<p align="center">
  <em>Screenshots coming soon — CLI output, campaign dashboard, OWASP report, mutation results</em>
</p>

<!--
![CLI Scan](docs/screenshots/cli-scan.png)
![Dashboard](docs/screenshots/dashboard.png)
![OWASP Report](docs/screenshots/owasp-report.png)
-->

---

## 💻 CLI Usage

### Scan a Target

```bash
# Quick scan with default attacks
phantom scan --target openai --model gpt-4

# Scan a custom endpoint
phantom scan --target-url http://localhost:8080/v1/chat --attack-set injection

# Scan with mutation engine enabled
phantom scan --target anthropic --model claude-3 --mutate --rounds 5
```

### Manage Campaigns

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
# HTML report
phantom report --campaign camp_abc123 --format html

# JSON export
phantom report --campaign camp_abc123 --format json

# OWASP LLM Top 10 compliance summary
phantom report --campaign camp_abc123 --format owasp
```

---

## 🛡️ OWASP LLM Top 10 Coverage

| ID | Risk Category | Phantom Coverage |
|----|---------------|------------------|
| **LLM01** | Prompt Injection | ✅ Direct & indirect injection attacks |
| **LLM02** | Insecure Output Handling | ✅ Output analysis and payload reflection |
| **LLM03** | Training Data Poisoning | ✅ Data extraction probes |
| **LLM04** | Model Denial of Service | ✅ Resource exhaustion payloads |
| **LLM05** | Supply Chain Vulnerabilities | ✅ Plugin and tool abuse vectors |
| **LLM06** | Sensitive Information Disclosure | ✅ PII and secret extraction attacks |
| **LLM07** | Insecure Plugin Design | ✅ Tool-call injection sequences |
| **LLM08** | Excessive Agency | ✅ Autonomy boundary tests |
| **LLM09** | Overreliance | ✅ Hallucination and confidence probes |
| **LLM10** | Model Theft | ✅ Model extraction and fingerprinting |

---

## 🏗️ Architecture

```
phantom/
├── core/             # Engine, mutation logic, result processing
├── attacks/          # Attack definitions and payload templates (YAML)
├── campaigns/        # Campaign orchestration and scheduling
├── targets/          # Target adapters (OpenAI, Anthropic, custom)
├── backend/          # Flask API and web dashboard
├── ui/               # Frontend assets for the dashboard
└── tests/            # Test suite
```

**Flow:** Attacks (YAML) → Mutation Engine → Campaign Orchestration → Target Delivery → Result Analysis → OWASP Report

## 🏁 Compared to Alternatives

| Feature | Phantom | Garak | PyRIT | Manual Testing |
|---------|---------|-------|-------|----------------|
| OWASP LLM Top 10 mapping | ✅ Full | ⚠️ Partial | ⚠️ Partial | ❌ |
| Mutation engine | ✅ Built-in | ✅ | ❌ | ❌ |
| Campaign management | ✅ | ❌ | ✅ | ❌ |
| Multi-target simultaneous | ✅ | ✅ | ✅ | ❌ |
| Web dashboard | ✅ | ❌ | ❌ | ❌ |
| Custom endpoint support | ✅ | ✅ | ✅ | ✅ |
| Report generation | ✅ HTML/JSON/OWASP | ⚠️ Basic | ⚠️ Basic | ❌ |

## 🛠️ Development

```bash
pip install -r requirements.txt
make test      # Run test suite
make lint      # Run linter
make run       # Start web dashboard
```

## 🤝 Contributing

Contributions are welcome — especially new attack patterns and target adapters!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-attack-vector`)
3. Commit your changes (`git commit -m 'Add new attack vector'`)
4. Push to the branch (`git push origin feature/new-attack-vector`)
5. Open a Pull Request

See the issues tab for areas where help is needed.

## ⚠️ Legal Disclaimer

Phantom is intended **strictly for authorized security testing and research**. Users must obtain explicit permission before testing any LLM system they do not own or operate. The authors assume no liability for misuse. By using this tool you agree to:

- ✅ Only test systems you have **written authorization** to test
- ✅ Comply with all applicable laws and **terms of service** of target providers
- ✅ Report vulnerabilities responsibly through **appropriate disclosure channels**

**Do not use Phantom for malicious purposes.** Unauthorized testing of AI systems may violate computer fraud laws.

## 📄 License

MIT

---

<p align="center">
  <strong>Phantom</strong> — Because the best defense starts with thinking like an attacker. 👻
</p>
