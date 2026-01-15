# LOLBAS Sysmon Rule Generator

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

🌍 *Read this in other languages: [English](README.md), [Русский](README-ru.md)*

---

A Python CLI utility for automatically generating Sysmon detection rules from [LOLBAS Project](https://lolbas-project.github.io/) (Living Off The Land Binaries and Scripts) data.

## Overview

LOLBAS Project documents legitimate Windows binaries that can be abused by attackers for malicious purposes. This tool automates the creation of Sysmon detection rules for these binaries, enriched with MITRE ATT&CK technique mappings.

### Key Features

- **Automatic Rule Generation** — Fetches LOLBAS Project data and generates Sysmon XML rules
- **Multiple Event Types** — Supports ProcessCreate (Event ID 1), ProcessAccess (Event ID 10), and FileCreate (Event ID 11)
- **Two Rule Types**:
  - **CommandLine rules** — More specific detection using executable + command-line flags
  - **Fallback rules** — Broader detection matching executable name only
- **MITRE ATT&CK Integration** — Enriches rules with technique IDs and names
- **Flexible Configuration** — TOML-based configuration for categories, mappings, and prefixes
- **Merge Support** — Merge generated rules with existing Sysmon configurations
- **Deduplication** — Optional `--unique-rules` flag to skip duplicate rules across categories

## Installation

### Prerequisites

- Python 3.11 or higher
- pip or another Python package manager

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/lolbas-sysmon-generator.git
cd lolbas-sysmon-generator
```

2. Install dependencies via pip:
```bash
pip install -r requirements.txt
```

3. Install via Poetry (alternative):
```bash
pip install poetry
poetry install --no-root
```

## Usage

### Basic Usage

Generate rules for all enabled categories:
```bash
python -m lolbas_sysmon
```

This will:
1. Fetch LOLBAS data (or use cached `lolbas.json`)
2. Fetch MITRE ATT&CK data (or use cached `enterprise-attack.json`)
3. Generate rules and save to `lolbas_rules.xml`

### Command-Line Options

```
usage: lolbas_sysmon [-h] [-i INPUT] [-o OUTPUT] [-f] [-c CONFIG]
                     [--category CATEGORY] [--dry-run] [--lolbas-json PATH]
                     [--mitre-json PATH] [--unique-rules]

Generate Sysmon detection rules from LOLBAS data

options:
  -h, --help            Show this help message and exit
  -i, --input INPUT     Input Sysmon config XML file to merge with
  -o, --output OUTPUT   Output XML file path (default: lolbas_rules.xml)
  -f, --force           Replace existing rules instead of skipping
  -c, --config CONFIG   Path to TOML configuration file
  --category CATEGORY   Comma-separated list of categories (e.g., Execute,Dump)
  --dry-run             Print generated rules without saving to file
  --lolbas-json PATH    Path to local LOLBAS JSON file
  --mitre-json PATH     Path to local MITRE ATT&CK JSON file
  --unique-rules        Skip duplicate rules for same executable within same event type
```

### Examples

**Generate rules for specific categories:**
```bash
python -m lolbas_sysmon --category "Execute,Download,Dump"
```

**Preview rules without saving (dry-run):**
```bash
python -m lolbas_sysmon --dry-run
```

**Merge with existing Sysmon config:**
```bash
python -m lolbas_sysmon -i sysmonconfig.xml -o merged_config.xml
```

**Force replace existing rules during merge:**
```bash
python -m lolbas_sysmon -i sysmonconfig.xml -o merged_config.xml --force
```

**Generate deduplicated rules:**
```bash
python -m lolbas_sysmon --unique-rules
```

**Use custom configuration:**
```bash
python -m lolbas_sysmon -c my_config.toml
```

### Docker Usage

Build image:
```bash
docker build -t lolbas-sysmon .
```

Generate rules (standalone):
```bash
docker run --rm -v .:/app lolbas-sysmon python -m lolbas_sysmon -o /app/lolbas_rules.xml
```

Merge with existing Sysmon config:
```bash
docker run --rm -v .:/app lolbas-sysmon \
  python -m lolbas_sysmon -i /app/sysmonconfig.xml -o /app/merged_config.xml
```

Use custom config and deduplication:
```bash
docker run --rm -v .:/app lolbas-sysmon \
  python -m lolbas_sysmon -c /app/config.toml --unique-rules -o /app/lolbas_rules.xml
```

## Configuration

The tool uses a TOML configuration file (`config.toml` by default).

### Categories

Enable or disable LOLBAS categories for rule generation:

```toml
[categories]
enabled = [
  "ADS",
  "AWL Bypass",
  "Compile",
  "Credentials",
  "Decode",
  "Download",
  "Dump",
  "Execute",
  # ... more categories
]
```

Available categories:
| Category | Description |
|----------|-------------|
| ADS | Alternate Data Stream operations |
| AWL Bypass | Application Whitelist bypass |
| Compile | Code compilation |
| Credentials | Credential access/dumping |
| Decode | Decode encoded payloads |
| Download | Download files from internet |
| Dump | Memory/process dumping |
| Encode | Encode payloads |
| Execute | Arbitrary code/command execution |
| Reconnaissance | System/network enumeration |
| Tamper | Modify system settings |
| UAC Bypass | User Account Control bypass |
| Upload | Data exfiltration |

### Event Type Mappings

Map categories to Sysmon event types:

```toml
[mappings]
"Execute" = "ProcessCreate"      # Event ID 1
"Credentials" = "ProcessAccess"  # Event ID 10
"Download" = "ProcessCreate"     # Event ID 1
"ADS" = "FileCreate"             # Event ID 11
```

### Rule Group Settings

```toml
[rule_groups]
prefix = "LOLBAS_"           # Prefix for fallback rules
cmd_prefix = "LOLBAS_CMD_"   # Prefix for CommandLine rules
unique_rules = false         # Enable deduplication by default
```

### Data Sources

```toml
[lolbas]
json_file = "lolbas.json"
url = "https://lolbas-project.github.io/api/lolbas.json"

[mitre]
json_file = "enterprise-attack.json"
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
```

## Output Format

Generated rules follow Sysmon XML schema:

```xml
<?xml version='1.0' encoding='utf-8'?>
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- CommandLine rules (more specific) -->
    <RuleGroup name="LOLBAS_CMD_Execute" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Download and execute a remote XSL script -->
        <Rule groupRelation="and" 
              name="technique_id=T1220,technique_name=XSL Script Processing">
          <OriginalFileName condition="is">wmic.exe</OriginalFileName>
          <CommandLine condition="contains any">/format</CommandLine>
        </Rule>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- Fallback rules (broader detection) -->
    <RuleGroup name="LOLBAS_Execute" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Windows Management Instrumentation Command -->
        <OriginalFileName condition="is"
              name="technique_id=T1220,technique_name=XSL Script Processing">
          wmic.exe
        </OriginalFileName>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

## How It Works

1. **Fetch Data** — Downloads LOLBAS JSON (list of LOLBins with commands, categories, MITRE mappings) and MITRE ATT&CK data (technique names)

2. **Parse & Filter** — Parses LOLBin entries and filters by enabled categories

3. **Generate Rules** — For each category:
   - Creates CommandLine rules (executable + specific flags from command examples)
   - Creates fallback rules (executable name/OriginalFileName only)

   > **Sysmon Schema Limitation:** CommandLine field is only available in ProcessCreate events. For categories mapped to FileCreate or ProcessAccess, only fallback rules are generated.

4. **Enrich with MITRE** — Adds `technique_id` and `technique_name` to rule attributes

5. **Output** — Saves standalone XML or merges with existing Sysmon config

## Deduplication Logic

With `--unique-rules` enabled:

- **CMD rules**: Deduplicated by `(executable, event_type, flags)` — same executable with same flags in same event type is skipped
- **Fallback rules**: Deduplicated by `(executable, event_type)` — same executable in same event type is skipped
- CMD and fallback rules are tracked separately (a CMD rule doesn't prevent a fallback rule)

## Testing

Run tests from the project root:

```bash
python -m pytest tests -v
```

If you use Poetry:

```bash
poetry run python -m pytest tests -v
```

## Development

### Pre-commit Hooks

This project uses pre-commit hooks to ensure code quality. Install them:

```bash
pip install pre-commit
pre-commit install
```

The hooks will automatically run on `git commit`:
- **ruff** — Code formatting and linting
- **trailing-whitespace** — Remove trailing whitespace
- **end-of-file-fixer** — Ensure files end with newline
- **check-yaml/toml** — Validate YAML and TOML syntax

Run hooks manually on all files:

```bash
pre-commit run --all-files
```

### Continuous Integration

GitHub Actions automatically runs on every push/PR:
- Tests on Python 3.13
- Linting with ruff
- Docker build verification

See `.github/workflows/ci.yml` for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [LOLBAS Project](https://lolbas-project.github.io/) — Living Off The Land Binaries and Scripts
- [MITRE ATT&CK](https://attack.mitre.org/) — Adversarial Tactics, Techniques, and Common Knowledge
- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) — System Monitor by Microsoft Sysinternals
- [Sysmon Modular](https://github.com/olafhartong/sysmon-modular) — Modular Sysmon configuration