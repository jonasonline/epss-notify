import requests
import pandas as pd
import gzip
import io

# URL for the EPSS feed
epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

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
    response = requests.get(nvd_base_url + cve_id)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch data for {cve_id}: Status code {response.status_code}")

# Download and extract the EPSS feed
epss_df = download_and_extract_epss(epss_url)

# Filter for CVEs with EPSS score greater than 0.5
high_risk_cves = epss_df[epss_df['epss'] > 0.5]

# Fetch NVD data for the first 20 high-risk CVEs
nvd_data = []
for cve_id in high_risk_cves['cve'].head(20):
    try:
        nvd_info = fetch_nvd_data(cve_id)
        nvd_data.append(nvd_info)
    except Exception as e:
        print(e)

# Display the fetched NVD data
for data in nvd_data:
    print(data)
