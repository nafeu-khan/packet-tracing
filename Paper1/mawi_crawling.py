import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import csv
import re
from collections import defaultdict
import time
import os

global prelocation_url
# prelocation_url="/content/drive/My Drive/"
prelocation_url="/"

# Generate URLs for fetching the data
def generate_urls(start_year, end_year):
    current_date = datetime(start_year, 1, 1, 14, 0)  # December 25th, 2:00 PM

    while current_date.year <= end_year:
        year = current_date.year
        formatted_date = current_date.strftime("%Y%m%d%H%M")
        url = f"https://mawi.wide.ad.jp/mawi/samplepoint-F/{year}/{formatted_date}.html"
        yield url

        current_date += timedelta(days=1)

# Parse the hierarchical data from the <pre> tag
def parse_pre_tag(pre_text):
    data = defaultdict(lambda: defaultdict(dict))  # Nested structure: data['ip']['tcp']['http']
    current_category = None
    current_subcategory = None
    # print(pre_text)
    lines = pre_text.strip().split("\n")
    for line in lines[2:]:
        # print("Line",line)

        # Match top-level categories like 'ip', 'ip6', etc.
        match_category = re.match(
            r'^\s*(\w+)\s+(\d+)\s+\(\s*(\d+\.\d+)%\)\s+(\d+)\s+\(\s*(\d+\.\d+)%\)\s+(\d+\.\d+)',
            line
        )
        if match_category and not line.startswith("  "):
            current_category = match_category.group(1)  # Category name (e.g., ip, ip6)
            current_subcategory = None

            # Store the data for the category
            data[current_category]['total'] = {
                'packets': match_category.group(2),
                'packets_percentage': match_category.group(3),
                'bytes': match_category.group(4),
                'bytes_percentage': match_category.group(5),
                'bytes_per_pkt': match_category.group(6)
            }
            continue

        # Match subcategories like 'tcp', 'udp', etc. (indented by 2 spaces)
        match_subcategory = re.match(
            r'^\s{2}(\S+)\s+(\d+)\s+\(\s*(\d+\.\d+)%\)\s+(\d+)\s+\(\s*(\d+\.\d+)%\)\s+(\d+\.\d+)',
            line
        )
        if match_subcategory:
            current_subcategory = match_subcategory.group(1).strip()
            data[current_category][current_subcategory]['total'] = {
                'packets': match_subcategory.group(2),
                'packets_percentage': match_subcategory.group(3),
                'bytes': match_subcategory.group(4),
                'bytes_percentage': match_subcategory.group(5),
                'bytes_per_pkt': match_subcategory.group(6)
            }
            continue

        # Match third-level data like 'http', 'https', etc. (indented by 3 spaces)
        match_data = re.match(
            r'^\s{3}(\w+)\s+(\d+)\s+\(\s*(\d+\.\d+)%\)\s+(\d+)\s+\(\s*(\d+\.\d+)%\)\s+(\d+\.\d+)',
            line
        )
        if match_data and current_category and current_subcategory:
            protocol = match_data.group(1)
            data[current_category][current_subcategory][protocol] = {
                'packets': match_data.group(2),
                'packets_percentage': match_data.group(3),
                'bytes': match_data.group(4),
                'bytes_percentage': match_data.group(5),
                'bytes_per_pkt': match_data.group(6)
            }
    return data

def extract_traffic_info(soup):
    info = {}

    # Look for traffic trace information
    traffic_info = soup.find('h3', string='Traffic Trace Info')
    if traffic_info:
        text = traffic_info.find_next('br').find_parent().text

        # Extract FileSize
        match_filesize = re.search(r'FileSize:\s+(\d+\.\d+MB)', text)
        if match_filesize:
            info['filesize'] = match_filesize.group(1)

    return info

def flatten_data(data, timestamp, filesize):
    flattened = defaultdict(list)

    for category, subcategories in data.items():
        for subcategory, protocols in subcategories.items():
            for protocol, metrics in protocols.items():
                if isinstance(metrics, dict):
                    flatten_row = {
                        "Timestamp": timestamp,
                        "FileSize": filesize,
                        "FileSize(MB)": float(re.search(r'(\d+\.\d+)([A-Z]+)', filesize).group(1)),
                        "Protocol": f"{subcategory}-{protocol}" if subcategory != 'total' else protocol,
                        **metrics
                    }
                    flattened[category].append(flatten_row)
                else:
                    # Handling invalid case properly
                    flatten_row = {
                        "Timestamp": timestamp,
                        "FileSize": filesize,
                        "FileSize(MB)": float(re.search(r'(\d+\.\d+)([A-Z]+)', filesize).group(1)),
                        "Protocol": f"{category}-{protocol}",
                        "packets": protocols.get('packets', ''),
                        "packets_percentage": protocols.get('packets_percentage', ''),
                        "bytes": protocols.get('bytes', ''),
                        "bytes_percentage": protocols.get('bytes_percentage', ''),
                        "bytes_per_pkt": protocols.get('bytes_per_pkt', ''),
                    }
                    flattened[category].append(flatten_row)  # Append to the correct list
                    break
    return flattened


# Extract data from the URL with retry mechanism
def extract_data(url, timestamp, max_retries=5, backoff_factor=2):
    for attempt in range(max_retries):
        try:
            print(f"Fetching URL: {url} (Attempt {attempt + 1}/{max_retries})")
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract traffic trace info
            traffic_info = extract_traffic_info(soup)
            filesize = traffic_info.get('filesize', 'Unknown')

            pre_tags = soup.find_all('pre')
            pre_tag = pre_tags[-1] if pre_tags else None

            if not pre_tag:
                print(f"No <pre> tag found in {url}")
                return {}
            # print("Pre Tag")
            # print(pre_tag.text)
            data = parse_pre_tag(pre_tag.text)
            return flatten_data(data, timestamp, filesize)

        except requests.exceptions.Timeout:
            print(f"Timeout error for {url}. Retrying...")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"404 Client Error for {url}. Modifying URL and retrying...")
                if "1359" not in url:
                    modified_url = url.replace("1400", "1359")
                    print(f"Retrying with modified URL: {modified_url}")
                    return extract_data(modified_url, timestamp, max_retries=max_retries, backoff_factor=backoff_factor)
                else:
                    print(f"Skipping, URL not found even after modification: {url}")
                    with open(f"{prelocation_url}extracted_data/skipped_urls.txt", "a") as file:
                        file.write(url +" "+ "\n")
                    return {}
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            if attempt == max_retries - 1:
                print(f"Max retries reached. Skipping {url}.")
                skipped_dir=f"{prelocation_url}extracted_data/skipped_urls.txt"
                print(skipped_dir)
                with open(skipped_dir, "a") as file:
                    file.write(url + "\n")
                return {}
        except Exception as e:
            print(f"Unexpected error: {e}")
            if attempt == max_retries - 1:
                print(f"Max retries reached. Skipping {url}.")
                skipped_dir=f"{prelocation_url}extracted_data/skipped_urls.txt"
                print(skipped_dir)
                with open(skipped_dir, "a") as file:
                    file.write(url + "\n")
                return {}

        # Exponential backoff
        time.sleep(backoff_factor ** attempt)

    return {}

# Create the directory structure if it doesn't exist
def create_directory_structure(filename):
    year = filename[:4]
    month = filename[4:6]
    day = filename[6:8]
    directory = f"{prelocation_url}extracted_data/{year}/{month}/{day}"
    os.makedirs(directory, exist_ok=True)
    return directory

# Save data to CSV
def save_to_csv(filename, data, headers):
    directory = create_directory_structure(filename)
    filepath = os.path.join(directory, filename)
    with open(filepath, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
        writer.writerows(data)
    print(f"Data saved to {directory}/{filename}")


# Main program
if __name__ == "__main__":
    start_year = 2022
    end_year = 2023

    headers = [
        "Timestamp", "FileSize","FileSize(MB)", "Protocol", "packets", "packets_percentage", "bytes", "bytes_percentage", "bytes_per_pkt"
    ]

    for url in generate_urls(start_year, end_year):
        timestamp = url.split('/')[-1].split('.')[0]
        print(f"Processing URL: {url}")
        year = timestamp[:4]
        month = timestamp[4:6]
        day = timestamp[6:8]
        directory = f"{prelocation_url}extracted_data/{year}/{month}/{day}"
        if os.path.exists(directory):
            print(f"Data already extracted for {url}")
            already_dir=f"{prelocation_url}extracted_data/already_extracted.txt"
            with open(already_dir, "a") as file:
                    file.write(url + "\n")
            continue
        extracted_data = extract_data(url, timestamp)
        if extracted_data:
            for category, data in extracted_data.items():
                filename = f"{timestamp}-{category}.csv"
                save_to_csv(filename, data, headers)
                # print(f"Data saved to {filename}")
        else:
            print(f"No data extracted for {url}")
