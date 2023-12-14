import requests
import pandas as pd
import gzip
import io
import json
import time

# Load configuration
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

# API configuration
nvd_api_key = config['nvd_api_key']
nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
headers = {'apiKey': nvd_api_key}

# URL for the EPSS feed
epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# Function to download and extract the EPSS feed
def download_and_extract_epss(url):
    response = requests.get(url)
    if response.status_code == 200:
        with gzip.open(io.BytesIO(response.content), 'rt') as f:
            # Skip the first row and set the header to the second row
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

# Download and extract the EPSS feed
epss_df = download_and_extract_epss(epss_url)

# Filter for CVEs with EPSS score greater than 0.5 and year 2015 or later
high_risk_cves = epss_df[(epss_df['epss'] > 0.5) & (epss_df['cve'].str.contains('CVE-201[5-9]|CVE-20[2-9]'))]

# Fetch NVD data for the first 20 high-risk CVEs from 2015 or later
nvd_data = []
for cve_id in high_risk_cves['cve'].head(20):
    try:
        nvd_info = fetch_nvd_data(cve_id)
        nvd_data.append(nvd_info)
        time.sleep(1)  # Wait for 1 second before making the next request
    except Exception as e:
        print(e)

# Display the fetched NVD data
for data in nvd_data:
    print(data)
