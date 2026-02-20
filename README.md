# Albator - macOS Hardening Toolkit

![Albator](albator.png)

**Albator** is a comprehensive macOS hardening toolkit designed for security professionals and power users. It combines robust shell scripts for system configuration with a modern Python framework for preflight checks, baseline validation, rollback management, and threat intelligence.

## 🚀 Key Features

- **Hardening Scripts**: Modular Bash scripts for Privacy, Firewall, Encryption, and App Security.
- **Preflight & Validation**: Python-based checks to ensure your environment meets minimum safety requirements before changes.
- **Rollback Capability**: Automated rollback of applied changes via JSON metadata (new!).
- **Threat Intelligence**: Fetch and analyze CVEs from GitHub, NVD, and Apple Security updates.
- **Unified CLI**: A single Python entry point (`albator_cli.py`) to orchestrate all tools.
- **Legacy Compatibility**: Includes the classic `albator.sh` orchestrator.

## 📂 Project Structure

| Component | File(s) | Description |
|---|---|---|
| **Unified CLI** | `albator_cli.py` | **Recommended entry point.** Runs preflight, hardening, and tools. |
| **Core Hardening** | `privacy.sh`, `firewall.sh`, `encryption.sh`, `app_security.sh` | Bash scripts implementing security controls. |
| **Rollback** | `rollback_apply.py` | Reverts changes using generated state metadata. |
| **Threat Intel** | `cve_fetch.sh`, `apple_updates.sh` | Fetches security advisories and update lists. |
| **Legacy** | `albator.sh` | Classic Bash orchestrator (ASCII art included). |
| **Validation** | `tests/*` | Shell and Python tests for compliance verification. |
| **Config** | `config/albator.yaml` | Runtime configuration (policies, versions). |

## 📦 Requirements

- **Python 3.8+**
- **Administrator privileges** (`sudo`) for hardening actions
- **Dependencies**: `curl`, `jq` (required), `pup` (optional for HTML parsing)

Install Python dependencies:
```bash
pip3 install -r requirements.txt
```

### macOS Compatibility

Albator is tested on current and upcoming macOS releases, including internal beta builds.

| macOS version | Support level | Notes |
|---|---|---|
| **26.x Tahoe** | ✅ Primary Dev Target | Current dev baseline (26.3 validated). Successor to Sequoia. 26.4 testing Monday. |
| **15.x (Sequoia)** | ✅ Supported | Production-stable target for current scripts. |
| **14.x (Sonoma)** | ⚠️ Best-effort | Many scripts work; some output signatures may differ. |
| **13.x and older** | ❌ Not supported | Use at your own risk; expect missing tooling and behavior drift. |

> **Note**: The default `min_macos_version` in `config/albator.yaml` is set to `26.3` to match the current beta environment. For production use on macOS 15.x, adjust `config/albator.yaml`:
> ```yaml
> preflight:
>   min_macos_version: "15.0"
>   enforce_min_version: true
> ```

## 🛠️ Quick Start

### 1. Preflight Checks
Ensure your system is ready and meets the defined baseline.
```bash
python3 albator_cli.py preflight --json
```

### 2. Apply Hardening
Run individual modules via the unified CLI (handles sudo prompts and logging).
```bash
python3 albator_cli.py privacy
python3 albator_cli.py firewall
python3 albator_cli.py encryption
python3 albator_cli.py app_security
```

*Note: Dry-run mode is available to simulate changes.*
```bash
python3 albator_cli.py --json-output privacy --dry-run
```

### 3. Rollback Changes
If a hardening script causes issues, use the generated metadata file (stored in `ALBATOR_STATE_DIR`) to revert.
```bash
# Dry run first
python3 rollback_apply.py --meta /tmp/albator_state/rollback_meta.json --dry-run

# Apply rollback
python3 rollback_apply.py --meta /tmp/albator_state/rollback_meta.json
```

### 4. Threat Intelligence
Fetch the latest security advisories:
```bash
# Fetch CVEs from GitHub/NVD
python3 albator_cli.py cve_fetch --dry-run

# Check for Apple software updates (offline cache supported)
python3 albator_cli.py apple_updates --offline --verbose
```

## ⚙️ Configuration

Runtime behavior is controlled by `config/albator.yaml`.
Key settings:
- `preflight.min_macos_version`: Enforce minimum OS version (e.g., "15.0").
- `preflight.enforce_min_version`: Boolean to block execution on older OS.

## 🏗️ Architecture

```mermaid
flowchart TD
    U["User"] --> C["albator_cli.py (Primary)"]
    U --> L["albator.sh (Legacy)"]
    U --> R["rollback_apply.py (Recovery)"]

    C --> P["preflight.py"]
    C --> S1["privacy.sh"]
    C --> S2["firewall.sh"]
    C --> S3["encryption.sh"]
    C --> S4["app_security.sh"]
    C --> S5["cve_fetch.sh"]
    C --> S6["apple_updates.sh"]

    L --> S1 & S2 & S3 & S4 & S5 & S6

    subgraph Core Logic
        S1 & S2 & S3 & S4
    end

    subgraph Intel
        S5 & S6
    end

    R -.-> |Reads| META["JSON Metadata"]
    Core Logic -.-> |Generates| META
```

## ⚠️ Notes & Limitations

- **State Directory**: Scripts generate rollback metadata in `/tmp/albator_state` (configurable via `ALBATOR_STATE_DIR`).
- **Offline Mode**: `apple_updates.sh` degrades gracefully if offline and cache is missing. Set `STRICT_OFFLINE=true` to force failure.
- **Enterprise Features**: `albator_enhanced.py` contains placeholders for advanced integrations (Fleet, Analytics) which depend on external `lib/` modules not present in the open-source release.

## 🤝 Contributing

See `CONTRIBUTING.md` for guidelines. Please open issues with reproducible test cases.

## 📄 License

MIT License.
