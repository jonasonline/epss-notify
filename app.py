import requests
import pandas as pd
import gzip
import io
import json
import time
import os
import re

# Load configuration
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

# API and Teams configuration
nvd_api_key = config['nvd_api_key']
teams_webhook_url = config.get('teams_webhook_url')  # Get webhook URL if exists
significant_increase_percent = config.get('significant_increase_percent', 20) / 100.0
nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
headers = {'apiKey': nvd_api_key}

# Function to post messages to Microsoft Teams
def post_to_teams(webhook_url, title, message):
    if webhook_url:
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "title": title,
            "text": message
        }
        response = requests.post(webhook_url, json=payload, headers={'Content-Type': 'application/json'})
        if response.status_code == 200:
            print("Message posted to Teams")
        else:
            print(f"Failed to post message to Teams: {response.status_code}")
    else:
        print("No Teams webhook URL provided in config.json, skipping post to Teams.")

# URL for the EPSS feed
epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# Function to download and extract the EPSS feed
def download_and_extract_epss(url):
    response = requests.get(url)
    if response.status_code == 200:
        with gzip.open(io.BytesIO(response.content), 'rt') as f:
            df = pd.read_csv(f, header=1)
        return df
    else:
        raise Exception(f"Failed to download file: Status code {response.status_code}")

# Function to fetch more information from NVD's database
def fetch_nvd_data(cve_id):
    response = requests.get(nvd_base_url + cve_id, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch data for {cve_id}: Status code {response.status_code}")

# Function to extract manufacturer from NVD data
def extract_manufacturer(nvd_data):
    manufacturers = set()

    nvd_text = json.dumps(nvd_data)
    criteria_matches = re.findall(r'"criteria":\s*"([^"]+)"', nvd_text)
    
    for criteria in criteria_matches:
        parts = criteria.split(':')
        if len(parts) > 3:
            manufacturers.add(parts[3])

    return list(manufacturers)

# Function to check if a CVE should be notified
def should_notify(cve_id, new_epss_score, existing_results):
    for result in existing_results:
        if result['cve_id'] == cve_id:
            old_epss_score = result['epss_score']
            increase = (new_epss_score - old_epss_score) / old_epss_score
            return increase >= significant_increase_percent
    return True  # Notify if it's a new CVE

# Function to load existing results from "cloud storage"
def load_existing_results(filename="nvd_results.json"):
    if os.path.exists(filename):
        with open(filename, "r") as file:
            return json.load(file)
    return []

# Function to simulate saving to cloud storage
def save_to_cloud_storage(data, filename="nvd_results.json"):
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

# Load existing results
existing_results = load_existing_results()

# Flag to determine if it's the first run (no previous results)
is_first_run = len(existing_results) == 0

# Download and extract the EPSS feed
epss_df = download_and_extract_epss(epss_url)

# Filter for CVEs with EPSS score greater than 0.5 and year 2015 or later
high_risk_cves = epss_df[(epss_df['epss'] > 0.5) & (epss_df['cve'].str.contains('CVE-201[5-9]|CVE-20[2-9]'))]

# Fetch NVD data for the first 20 high-risk CVEs from 2015 or later
all_results = []
for cve_id, epss_score in zip(high_risk_cves['cve'].head(20), high_risk_cves['epss'].head(20)):
    try:
        nvd_data = fetch_nvd_data(cve_id)
        manufacturers = extract_manufacturer(nvd_data)
        # Only notify if it's not the first run and the conditions are met
        if not is_first_run and should_notify(cve_id, epss_score, existing_results):
            post_to_teams(teams_webhook_url, f"Update for {cve_id}", f"EPSS Score: {epss_score}, Manufacturers: {', '.join(manufacturers)}")
        all_results.append({"cve_id": cve_id, "epss_score": epss_score, "manufacturers": manufacturers})
        time.sleep(1)  # Rate limiting
    except Exception as e:
        print(e)

# Save all new and updated results
save_to_cloud_storage(all_results)
