<<<<<<< HEAD
![Albator](albator.png)

# macOS Security Compliance Project
=======
# Albator - macOS 15 Hardening Tool  

![Albator](albator.png)

A series of scripts to harden macOS 15 (Sequoia) for security and privacy, inspired by NIST guidelines. Suitable for power users and novices alike. This project evolved from the macOS Security Compliance Project, a Python-based tool, with the current focus on Bash scripts while preserving legacy features.  

## Usage  
Run the main script with options to harden specific areas or fetch security advisories:  

```bash
./albator.sh [options]

### Options  
- `-f, --firewall`: Enable and configure the firewall  
- `-p, --privacy`: Adjust privacy settings (e.g., disable telemetry, configure Safari)  
- `-e, --encryption`: Enable FileVault encryption  
- `-s, --app-security`: Enable Gatekeeper and verify Hardened Runtime  
- `-c, --cve`: Fetch recent CVE advisories relevant to macOS  
- `-a, --apple`: Fetch Apple security updates for macOS Sequoia 15  
- `-h, --help`: Display help message  

### Example  
To fetch CVE advisories, Apple security updates, and enable the firewall:  

```bash
./albator.sh --cve --apple --firewall
```

## Requirements  
- macOS 15 (Sequoia)  
- Administrator privileges (sudo access)  
- `curl` and `jq` for fetching CVE advisories (`brew install jq`)  
- `pup` for parsing Apple security updates (`brew install pup`, optional but recommended)  

## Features  
- Modular scripts for targeted hardening (firewall, privacy, encryption, app security)  
- NIST-inspired security standards  
- Disables unnecessary services (remote login, remote management, mDNS multicast)  
- CVE advisory fetching to keep users informed about potential vulnerabilities  
- Cross-referencing with Apple’s security updates for a comprehensive view of macOS vulnerabilities  

## Security Rules  
- **Disable Guest Account**  
- **Enable System Integrity Protection (SIP)**  
- **Enable Gatekeeper**  
- **Disable Bluetooth**  
- **Disable Root Account**  
- **Require Password for Screensaver**  
- **Enable Firewall**  
- **Enable Software Updates**  
- **Disable SSH**  
- **Disable Remote Management**  
- **Secure Keyboard Settings**  
- **Disable Wi-Fi**  
- **Enable FileVault**  
- **Enable Lockdown Mode**  

## Notes and Limitations  
- Some changes (e.g., FileVault) may require a system restart.  
- Always back up your system before applying hardening scripts.  
- CVE and Apple updates fetching require an internet connection.  

## Contributing  
Feel free to submit issues or pull requests to improve Albator, including enhancements to the Bash scripts or revival of Python features!  
>>>>>>> edd7c1348c8bd688ed4da3c14fc23a91ade5dfe4

## License  
Open-source under the MIT License.  

<<<<<<< HEAD
The tool supports multiple interfaces—**command-line, interactive mode, and a graphical user interface (GUI)**—making it accessible to both power users and novices aiming to harden their macOS systems.

## Features
- **Rule Collection**: Aggregates security rules from `rules/` and `custom/rules/` directories.
- **Baseline Generation**: Creates YAML security baselines (e.g., STIG) based on keyword tags.
- **Control Verification**: Checks compliance against **NIST 800-53** controls.
- **Tailoring**: Customizes baselines with user-specific configurations and Organizational Defined Values (ODVs).
- **Fix Application**: Applies security fixes directly to the system, with prompts for confirmation (some require `sudo`).
- **Interfaces**:
  - **Command-Line**: Use flags like `-l`, `-k`, `-c`, `-t`, `-i`, `--gui`.
  - **Interactive Mode**: Run with `-i` for a command-line prompt experience.
  - **GUI Mode**: Launch with `--gui` for a window with radio buttons to select actions.

## Supported macOS Version
- **macOS 15.4 (Sequoia)**, with rules adapted from **NIST Revision 1.1** guidance for macOS 15.0 (December 16, 2024) and customized for 15.4.

## Prerequisites
- **Python 3.9+**: Pre-installed on macOS 15.4 or available via Homebrew:
  ```bash
  brew install python
  ```
- **Dependencies**:
  ```bash
  pip install pyyaml
  ```
- **Tkinter**: Included with Python for GUI mode; ensure Xcode is installed for full compatibility:
  ```bash
  xcode-select --install
  ```
- **Sudo Access**: Required for applying system-level security fixes.

## Installation
1. **Set Up Directory**:
   ```bash
   mkdir -p ~/macoshardening/MACOS_HARDENING
   cd ~/macoshardening/MACOS_HARDENING
   ```
2. **Create necessary subdirectories**:
   ```bash
   mkdir -p rules custom/rules includes build/baselines
   ```
3. **Install Python Dependencies**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install pyyaml
   ```
4. **Verify Files**:
   Ensure the following files exist:
   ```
   main.py, arg_parser.py, rule_handler.py, utils.py, VERSION.yaml, 
   includes/800-53_baselines.yaml, includes/mscp-data.yaml, rules/*.yaml
   ```

## Usage
### Command-Line Mode
- **List Tags**:
  ```bash
  python main.py -l
  ```
- **Generate Baseline**:
  ```bash
  python main.py -k stig
  ```
  (You can also set the ROOT_DIR environment variable to specify the root directory: `ROOT_DIR=/path/to/root python main.py -k stig`)
- **Check Controls**:
  ```bash
  python main.py -c
  ```
- **Tailor Baseline**:
  ```bash
  python main.py -k stig -t
  ```

### Interactive Mode
- Start:
  ```bash
  sudo python main.py -i
  ```
- Commands:
  - `list`: Display all tags (e.g., `stig`, `security`).
  - `generate <tag>`: Create a baseline (e.g., `generate stig`).
  - `check`: Verify NIST 800-53 control coverage.
  - `tailor <tag>`: Customize a baseline (e.g., `tailor stig`).
  - `apply <tag>`: Apply fixes for rules with the tag (e.g., `apply stig`).
  - `exit`: Quit interactive mode.

### GUI Mode
- Start:
  ```bash
  sudo python main.py --gui
  ```
- Interface:
  - **Radio buttons** for: List Tags, Generate Baseline, Check Controls, Tailor Baseline, Apply Fixes.
  - Click **"Proceed"** to execute the selected action, follow prompts as needed.

**Note**: Use `sudo` for commands applying fixes (e.g., `apply`) that modify system settings.

## Project Structure
```
macoshardening/
├── MACOS_HARDENING/
│   ├── main.py            # Core script with CLI, interactive, and GUI modes
│   ├── arg_parser.py      # Command-line argument parsing
│   ├── rule_handler.py    # Rule collection, control checking, baseline generation
│   ├── utils.py           # Utility functions
│   ├── includes/          # Configuration files
│   │   ├── 800-53_baselines.yaml  # NIST 800-53 control baselines
│   │   └── mscp-data.yaml         # Metadata for authors and titles
│   ├── VERSION.yaml       # macOS version info
│   ├── build/             # Generated outputs
│   │   └── baselines/     # Baseline YAML files (e.g., stig.yaml)
│   └── venv/              # Virtual environment (optional)
├── rules/                 # Security rule YAML files
├── custom/                # Optional custom rule overrides
└── README.md              # This documentation
```

## Security Rules
The tool applies the following security measures:
- **Disable Guest Account** (`os_guest_account_disable`)
- **Enable System Integrity Protection** (`os_sip_enable`)
- **Enable Gatekeeper** (`os_gatekeeper_enable`)
- **Disable Bluetooth** (`os_bluetooth_disable`)
- **Disable Root Account** (`os_root_disable`)
- **Require Password for Screensaver** (`os_screensaver_password`)
- **Enable Firewall** (`os_firewall_enable`)
- **Enable Software Updates** (`os_software_update_auto`)
- **Disable SSH** (`os_ssh_disable`)
- **Disable Remote Management** (`os_remote_management_disable`)
- **Secure Keyboard Settings** (`os_keyboard_secure`)
- **Disable Wi-Fi** (`os_wifi_disable`)
- **Enable FileVault** (`os_filevault_enable`)
- **Enable Lockdown Mode** (`os_lockdown_enable`)

## Known Limitations
- **Manual Fixes**: Some rules (e.g., FileVault, Lockdown Mode) require manual steps due to GUI dependencies.
- **Sudo Requirement**: Many fixes need root privileges; run with `sudo` for full functionality.
- **macOS 15.4 Specificity**: Rules are based on Sequoia 15.0 guidance; verify compatibility with 15.4 updates.

## Contributing
- Add new rules to `rules/` or improve scripts.
- Submit feedback or enhancements via issues or pull requests if hosted on a repository.

## License
Open-source under the MIT License.

## Acknowledgments
- Built on **NIST macOS Security Guidelines** (Revision 1.1, 2024).
- Inspired by the [macOS Security and Privacy Guide](#macos-security-and-privacy-guide).
- Developed by **Maxime at Cyberdyne Systems**.
=======
## Acknowledgments  
- Built on **NIST macOS Security Guidelines (Revision 1.1, 2024)**.  
- Inspired by the **macOS Security and Privacy Guide** and **Derrick**: [https://github.com/supdevinci/derrick](https://github.com/supdevinci/derrick).  
- Developed by **Maxime at Cyberdyne Systems**.  
```
>>>>>>> edd7c1348c8bd688ed4da3c14fc23a91ade5dfe4
