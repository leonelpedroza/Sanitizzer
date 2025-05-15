# Config Sanitizer Tool

## History

In many of my roles installing and maintaining network equipment, I've had to interact with suppliers and manufacturers of communications equipment on several occasions regarding unexpected behaviour and specific inquiries. In almost every case, the support engineer requests a copy of the equipment configuration.

In my usual cybersecurity paranoia, I never found it very convenient to send configuration files and leave them "_into the wild_" on the internet.

I created this program about three years ago to clean sensitive data from configurations, setups, and event logs before sending them. This information mainly includes passwords, usernames, encryption keys, and tokens, among other things.

This Python program has covered my basic needs for quite some time, so I asked my friend Claude AI LLM to organize it, add comments, improve error handling, make it more modular and readable, and adhere to the Python PEP-8 programming standard.


## Introduction

A powerful, user-friendly tool for sanitizing network device configuration files by removing sensitive information like passwords, certificates, keys, and authentication credentials.

![Config Sanitizer Tool Screenshot](screenshot.png)

## Features

- **Multi-Vendor Support**: Sanitizes configuration files from Cisco, Fortinet, Juniper, Huawei, Palo Alto, and Gigamon devices.
- **Auto-Detection**: Automatically identifies device type from configuration content.
- **Preview Mode**: Side-by-side comparison of original and sanitized content before making changes.
- **External Password Management**: Define custom sensitive passwords in an external file.
- **Automatic Backup**: Creates backups of original files before sanitization.
- **Multi-threading**: Responsive UI during sanitization of large files.
- **Comprehensive Logging**: Detailed logs of all operations.

## Why Config Sanitizer?

Network engineers often need to share configuration files with vendors, colleagues, or support teams. However, these files typically contain sensitive credentials and keys that shouldn't be exposed. Config Sanitizer automatically removes this sensitive information while preserving the structure of the configuration file, making it safe to share.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/config-sanitizer.git

# Navigate to the project directory
cd config-sanitizer

# Install dependencies (if required)
pip install -r requirements.txt

# Run the application
python sanitizer.py
```

## Usage

1. Launch the application
2. Select a configuration file using the "Browse Files" button
3. Choose a device type or use auto-detection
4. Click "Preview" to see what will be changed
5. Click "SANITIZE" to process the file
6. A sanitized version of your file will be saved with timestamp in the same directory

## Supported Patterns

The tool sanitizes the following sensitive information:

- Passwords and secrets
- SNMP community strings
- Authentication keys
- SSH keys
- Certificates and encrypted content
- API tokens
- Shared secrets
- And much more!

## Customization

- Add your own passwords to the `secret.txt` file
- Edit vendor-specific patterns in the code
- Contribute additional vendor support by adding new sanitization methods

## Requirements

- Python 3.6+
- Tkinter (included with most Python installations)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Originally created by lgp DevOps (March 2022)
- Enhanced version with additional features (2025)
