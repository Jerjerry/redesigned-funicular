# iOS Certificate Validator

A cross-platform tool for validating iOS certificates and provisioning profiles.

## Features

- Validate P12 certificates
- Validate provisioning profiles
- Check certificate and profile compatibility
- Verify expiration dates
- User-friendly GUI interface

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Jerjerry/redesigned-funicular.git
cd redesigned-funicular
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the GUI:
```bash
python src/cert_validator_gui.py
```

### Features

1. Certificate Validation:
   - Load and validate P12 certificates
   - Check expiration dates
   - Verify private key presence
   - Display certificate details

2. Provisioning Profile Validation:
   - Parse and validate mobileprovision files
   - Check expiration dates
   - Display included devices
   - Show entitlements

3. Compatibility Check:
   - Verify if certificate is included in profile
   - Check team ID matches
   - Validate entitlements

## Development

- Python 3.11+
- Uses `cryptography` for certificate operations
- Tkinter for GUI

## License

MIT License
