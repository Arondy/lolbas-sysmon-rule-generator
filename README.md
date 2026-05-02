# LOLBAS Sysmon Rule Generator

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

🌍 *Read this in other languages: [English](README.md), [Русский](README-ru.md)*

---

A Python CLI utility for automatically generating Sysmon detection rules from [LOLBAS Project](https://lolbas-project.github.io/) (Living Off The Land Binaries and Scripts) data, enriched with [Sigma Rules](https://github.com/SigmaHQ/sigma) and [MITRE ATT&CK](https://attack.mitre.org/) mappings.

## Overview

LOLBAS Project documents legitimate Windows binaries that can be abused by attackers for malicious purposes. This tool automates the creation of Sysmon detection rules for these binaries, combining three data sources for maximum detection coverage:

1. **LOLBAS Project** — LOLBin definitions with command examples and categories
2. **Sigma Rules** — Community detection rules referenced in LOLBAS entries
3. **MITRE ATT&CK** — Technique IDs and names for rule annotation

### Key Features

- **Automatic Rule Generation** — Fetches LOLBAS Project data and generates Sysmon XML rules
- **Sigma Rule Enrichment** — Downloads and parses Sigma detection rules from LOLBAS references for more precise CommandLine rules (takes priority over extracted flags)
- **Multiple Event Types** — Supports ProcessCreate (Event ID 1), NetworkConnect (Event ID 3), ImageLoad (Event ID 7), ProcessAccess (Event ID 10), and FileCreate (Event ID 11)
- **Two Rule Types**:
  - **CommandLine rules** — More specific detection using executable + command-line flags (from Sigma or LOLBAS command examples)
  - **Fallback rules** — Broader detection matching executable name only
- **MITRE ATT&CK Integration** — Enriches rules with technique IDs and names
- **Smart Caching** — All external data (LOLBAS, MITRE, Sigma) is cached locally with configurable auto-update (default: 28 days)
- **Flexible Configuration** — TOML-based configuration for categories, mappings, and prefixes
- **Merge Support** — Merge generated rules with existing Sysmon configurations
- **Coverage Analysis** — Analyze how many LOLBins are covered by an existing Sysmon config
- **Deduplication** — Optional `--unique-rules` flag to skip duplicate rules across categories
- **Detailed Statistics** — Sigma enrichment summary with download/parse/skip counters
- **Rule Testing** — [ART-LOLBIN-Tests](ART-LOLBIN-Tests/) subproject for automated Sysmon rule testing using Atomic Red Team scenarios

## Installation

### Prerequisites

- Python 3.11 or higher
- pip or another Python package manager

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Arondy/lolbas-sysmon-rule-generator.git
cd lolbas-sysmon-rule-generator
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
3. Download and parse Sigma rules referenced in LOLBAS entries
4. Generate rules and save to `lolbas_rules.xml`

### Command-Line Options

```
usage: lolbas_sysmon [-h] [-i INPUT] [-o OUTPUT] [-f] [-c CONFIG]
                     [--category CATEGORY] [--dry-run] [--lolbas-json PATH]
                     [--mitre-json PATH] [--unique-rules] [--coverage]
                     [--show-missing] [--show-covered] [--only-cmd | --only-fallback]
                     [--update-data] [--update-lolbas] [--update-mitre]
                     [--no-sigma] [--update-sigma]

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
  --coverage            Analyze LOLBAS coverage in existing Sysmon config (requires -i)
  --show-missing        Show list of LOLBins missing from config (use with --coverage)
  --show-covered        Show list of LOLBins covered in config (use with --coverage)
  --only-cmd            Generate only CommandLine rules (more specific)
  --only-fallback       Generate only fallback rules (executable name only)
  --update-data         Force re-download of LOLBAS, MITRE, and Sigma data
  --update-lolbas       Force re-download of LOLBAS JSON data from URL
  --update-mitre        Force re-download of MITRE ATT&CK JSON data from URL
  --no-sigma            Disable Sigma-based rule enrichment
  --update-sigma        Force re-download of cached Sigma rules
  --include-group-name  Include rule group name in the 'name' attribute of each rule
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

**Generate only CommandLine rules (without fallback):**
```bash
python -m lolbas_sysmon --only-cmd
```

**Generate only fallback rules (without CommandLine):**
```bash
python -m lolbas_sysmon --only-fallback
```

**Disable Sigma enrichment (use only LOLBAS command examples):**
```bash
python -m lolbas_sysmon --no-sigma
```

**Force update all cached data:**
```bash
python -m lolbas_sysmon --update-data
```

**Force update only Sigma rules:**
```bash
python -m lolbas_sysmon --update-sigma
```

**Include group name in rule attributes:**
```bash
python -m lolbas_sysmon --include-group-name
```

**Show covered and missing LOLBins:**
```bash
python -m lolbas_sysmon --coverage -i sysmonconfig.xml --show-covered --show-missing
```

**Use custom configuration:**
```bash
python -m lolbas_sysmon -c my_config.toml
```

**Force update LOLBAS and MITRE data:**
```bash
python -m lolbas_sysmon --update-data
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
  "Conceal",
  "Copy",
  "Credentials",
  "Decode",
  "Download",
  "Dump",
  "Encode",
  "Execute",
  "Reconnaissance",
  "Tamper",
  "UAC Bypass",
  "Upload",
]
```

Available categories:
| Category | Description |
|----------|-------------|
| ADS | Alternate Data Stream operations |
| AWL Bypass | Application Whitelist bypass |
| Compile | Code compilation |
| Conceal | Hide malicious activity |
| Copy | File copy operations |
| Credentials | Credential access/dumping |
| Decode | Decode encoded payloads |
| Download | Download files from internet |
| Dump | Memory/process dumping |
| Encode | Encode payloads |
| Execute | Arbitrary code/command execution |
| Reconnaissance | System/network enumeration |
| Tamper | Modify system settings/files |
| UAC Bypass | User Account Control bypass |
| Upload | Data exfiltration |

### Event Type Mappings

Map categories to one or more Sysmon event types:

```toml
[mappings]
"Execute" = ["ProcessCreate", "ImageLoad"]    # Event ID 1, 7
"Download" = ["ProcessCreate", "NetworkConnect"]  # Event ID 1, 3
"Credentials" = ["ProcessAccess"]             # Event ID 10
"ADS" = ["FileCreate"]                        # Event ID 11
"Dump" = ["ProcessAccess", "ImageLoad"]       # Event ID 10, 7
```

> **Note:** ImageLoad rules are only generated for LOLBins with `.dll` extension.

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
auto_update = true
max_age_days = 28

[mitre]
json_file = "enterprise-attack.json"
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
auto_update = true
max_age_days = 28
```

### Sigma Configuration

```toml
[sigma]
enabled = true
cache_dir = "cache_sigma_rules"
auto_update = true
max_age_days = 28
```

## Output Format

Generated rules follow Sysmon XML schema:

```xml
<?xml version='1.0' encoding='utf-8'?>
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- CommandLine rules (more specific, Sigma-enriched) -->
    <RuleGroup name="LOLBAS_CMD_Execute" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Sigma: Suspicious Certutil Command Usage | Level: high | ID: e011a729-... -->
        <Rule groupRelation="and"
              name="technique_id=T1027,technique_name=Obfuscated Files or Information">
          <OriginalFileName condition="is">CertUtil.exe</OriginalFileName>
          <CommandLine condition="contains any">-decode;-decodehex;-urlcache;-encode</CommandLine>
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

2. **Sigma Enrichment** — Downloads Sigma detection rules referenced in LOLBAS entries, parses detection blocks and condition expressions, and attaches convertible rules to LOLBins

3. **Parse & Filter** — Parses LOLBin entries and filters by enabled categories

4. **Generate Rules** — For each category and event type:
   - Creates CommandLine rules using Sigma rules (priority) or LOLBAS command flags (fallback)
   - Creates fallback rules (executable name/OriginalFileName only)
   - ImageLoad rules are generated only for `.dll` LOLBins

   > **Sysmon Schema Limitation:** CommandLine field is only available in ProcessCreate events. For categories mapped to FileCreate, ProcessAccess, NetworkConnect, or ImageLoad, only fallback rules are generated.

5. **Enrich with MITRE** — Adds `technique_id` and `technique_name` to rule attributes

6. **Output** — Saves standalone XML or merges with existing Sysmon config

### Sigma Enrichment Details

The tool downloads Sigma YAML files from URLs found in LOLBAS `Detection` sections, converts GitHub blob URLs to raw content URLs, and parses them using [pySigma](https://github.com/SigmaHQ/pySigma). Supported Sigma features:

- **Logsource categories**: `process_creation`, `file_event`, `network_connection`, `image_load`, `process_access`, `registry_event`
- **Condition logic**: `and`, `or`, `not`, `1 of selection_*`, `all of selection_*`, parenthesized expressions
- **Field modifiers**: `contains`, `startswith`, `endswith`, `contains|all`, `contains|any`

After enrichment, a detailed statistics summary is logged:

```
Sigma enrichment summary:
  URLs: 292 total, 258 downloaded, 34 cached, 0 failed
  Rules: 254 parsed, 231 convertible
  Skipped: 15 (unsupported fields), 8 (unsupported features)
  LOLBins enriched: 176
  Top skip reasons: feature:re: 8, field:Initiated: 4, field:Description: 3
```

## Coverage Analysis

The `--coverage` flag analyzes how many LOLBins from the LOLBAS project are covered by existing Sysmon configuration:

Example output:
```
LOLBAS Coverage Report

Total LOLBins in LOLBAS:    227
Covered in config:          97
Missing from config:        130
Coverage:                   42.7%
CMD Rules:                  85
Fallback rules:             97
```

A LOLBin is considered "covered" if its `Name` or `OriginalFileName` appears in any rule within the config (Image, OriginalFileName, SourceImage, TargetImage, or ImageLoaded tags).

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

## Atomic Red Team Rule Testing

`ART-LOLBIN-Tests/` is designed for automated testing of Sysmon rules for the ability to detect LOLBin attacks. Uses scenarios from the [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) database.

### Features

- Automatic search for LOLBin techniques in Atomic Red Team
- Configuration generation for test runs
- Collection and analysis of Sysmon events around test execution
- Detection quality assessment: TP, FN, recall
- Support for saving intermediate results

### Quick Start

```bash
cd ART-LOLBIN-Tests
.\AtomicRedTeam_LOLBIN_TESTS.ps1
python main.py --config ART_lolbin_tests/config_generated.json --output test_results/results.json
```

See [README](ART-LOLBIN-Tests/README.md) in the folder for details.

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
- Tests on Python 3.11-3.13
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
- [Sigma Rules](https://github.com/SigmaHQ/sigma) — Generic Signature Format for SIEM Systems
- [pySigma](https://github.com/SigmaHQ/pySigma) — Python library for Sigma rule processing
- [MITRE ATT&CK](https://attack.mitre.org/) — Adversarial Tactics, Techniques, and Common Knowledge
- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) — System Monitor by Microsoft Sysinternals
- [Sysmon Modular](https://github.com/olafhartong/sysmon-modular) — Modular Sysmon configuration
