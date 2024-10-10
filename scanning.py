# This software is licensed under the MIT License.
# See the LICENSE file for details.


import time
import requests
import logging
import json
from tkinter import messagebox

# Load API keys from config.json
def load_api_keys():
    try:
        with open('config.json', 'r') as config_file:
            config_data = json.load(config_file)
            api_key_vt = config_data.get('API_KEY_VT', '')
            api_key_abuseipdb = config_data.get('API_KEY_ABUSEIPDB', '')
            
            if not api_key_vt or not api_key_abuseipdb:
                raise ValueError("API keys are missing in config.json")
            
            return api_key_vt, api_key_abuseipdb
    
    except FileNotFoundError:
        logging.error("config.json file not found.")
        messagebox.showerror("Error", "config.json file not found.")
        return None, None
    except ValueError as e:
        logging.error(str(e))
        messagebox.showerror("Error", str(e))
        return None, None

API_KEY_VT, API_KEY_ABUSEIPDB = load_api_keys()  # Load keys from config

MAX_RETRIES = 3  # You can adjust this based on your needs

def virustotal_scan(ip, retries=0):
    if not API_KEY_VT:  # Check if API keys are loaded
        return None
    
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        'x-apikey': API_KEY_VT
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        logging.info(f"VirusTotal response for {ip}: {data}")
        
        # Extract necessary fields
        malicious_count = data['data']['attributes']['last_analysis_stats'].get('malicious', 0)
        suspicious_count = data['data']['attributes']['last_analysis_stats'].get('suspicious', 0)
        geolocation = data['data']['attributes'].get('country', 'N/A')
        company = data['data']['attributes'].get('as_owner', 'N/A')

        return {
            "IP": ip,
            "Source": "VirusTotal",
            "Malicious": malicious_count,
            "Suspicious": suspicious_count,
            "Geolocation": geolocation,
            "Company": company
        }

    except requests.Timeout:
        logging.error(f"Timeout while querying VirusTotal for {ip}")
        return None

    except requests.RequestException as e:
        if response.status_code == 429:  # Rate limit exceeded
            if retries < MAX_RETRIES:
                retry_msg = f"VirusTotal rate limit exceeded. Retrying in 60 seconds... (Attempt {retries + 1}/{MAX_RETRIES})"
                logging.warning(retry_msg)
                
                # Show warning in the UI (messagebox)
                messagebox.showwarning("VirusTotal Rate Limit Exceeded", retry_msg)
                
                time.sleep(60)  # Wait 60 seconds before retrying
                return virustotal_scan(ip, retries + 1)  # Retry the scan

            else:
                # Maximum retries reached, log and show a final warning to the user
                error_msg = f"VirusTotal rate limit exceeded. Maximum retries ({MAX_RETRIES}) reached. Skipping {ip}."
                logging.error(error_msg)
                
                # Show the error message in the UI
                messagebox.showerror("VirusTotal Rate Limit Exceeded", error_msg)
                
                return None

        logging.error(f"Error querying VirusTotal for {ip}: {e}")
        return None

def abuseipdb_scan(ip, retries=0):
    if not API_KEY_ABUSEIPDB:  # Check if API keys are loaded
        return None
    
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': API_KEY_ABUSEIPDB,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 30
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        logging.info(f"AbuseIPDB response for {ip}: {data}")

        scan_results = {
            "IP": ip,
            "Source": "AbuseIPDB",
            "Reputation": data['data']['abuseConfidenceScore'],
            "Malicious Reports": data['data']['totalReports'],
            "Geolocation": {
                "Country": data['data'].get('countryCode', 'N/A'),
                "City": data['data'].get('city', 'N/A'),
                "ISP": data['data'].get('isp', 'N/A')
            },
            "Last Reported": data['data'].get('lastReportedAt', 'N/A'),
            "Domain": data['data'].get('domain', 'N/A')
        }

        return scan_results

    except requests.Timeout:
        logging.error(f"Timeout while querying AbuseIPDB for {ip}")
        return None

    except requests.RequestException as e:
        if response.status_code == 429:  # Rate limit exceeded
            if retries < MAX_RETRIES:
                retry_msg = f"Rate limit exceeded for AbuseIPDB. Retrying in 60 seconds... (Attempt {retries + 1}/{MAX_RETRIES})"
                logging.warning(retry_msg)
                
                # Show warning in the UI (messagebox)
                messagebox.showwarning("AbuseIPDB Rate Limit Exceeded", retry_msg)
                
                time.sleep(60)  # Wait 60 seconds before retrying
                return abuseipdb_scan(ip, retries + 1)  # Retry the scan

            else:
                # Maximum retries reached, log and show a final warning to the user
                error_msg = f"AbuseIPDB rate limit exceeded. Maximum retries ({MAX_RETRIES}) reached. Skipping {ip}."
                logging.error(error_msg)
                
                # Show the error message in the UI
                messagebox.showerror("AbuseIPDB Rate Limit Exceeded", error_msg)
                
                return None

        logging.error(f"Error querying AbuseIPDB for {ip}: {e}")
        return None
