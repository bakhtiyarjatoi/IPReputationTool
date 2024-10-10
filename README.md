# IP Reputation Tool

## Overview
The IP Reputation Tool is a Python-based application that checks the reputation of IP addresses using the VirusTotal and AbuseIPDB APIs. It provides a graphical user interface (GUI) built with Tkinter, making it easy for users to interact with the tool and analyze IP reputation data effectively.

## Features
- **IP Reputation Check**: Validate IP addresses using VirusTotal and AbuseIPDB APIs.
- **User-Friendly GUI**: Built with Tkinter for an intuitive user experience.
- **Multi-Format Support**: Accepts IP lists in Excel, CSV, TXT, and JSON formats.
- **Scan History**: View previously scanned IPs and their results.
- **Configuration Options**: Customize API keys and settings through the GUI.
- **Error Handling**: Robust error handling to ensure smooth operation.
- **Logging**: Keeps track of scan results and activities.

## Installation

### Prerequisites
- Python 3.x
- Required Python libraries (listed below)

### Required Libraries
You can install the required libraries using `pip`. Run the following command:

```bash
pip install -r requirements.txt


## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contribution
We welcome contributions from the community! Please fork the repository and submit a pull request for any enhancements or bug fixes.

## Configuration
The tool uses a `config.json` file to store API keys. When you first run the tool, make sure to configure your API keys for VirusTotal and AbuseIPDB.

### Edit config.json
You can update the API keys in the `config.json` file.
