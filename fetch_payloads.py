import requests
import csv
import json
from io import StringIO

def fetch_and_process_csv():
    """Fetch the CSV file and extract all payloads"""
    url = "https://hebbkx1anhila5yf.public.blob.vercel-storage.com/mbih-sMnUAT6lQhw8tUQGPqjvcDNMzRd9eM.csv"
    
    try:
        print("Fetching CSV file...")
        response = requests.get(url)
        response.raise_for_status()
        
        # Parse CSV content
        csv_content = StringIO(response.text)
        csv_reader = csv.reader(csv_content)
        
        # Get headers
        headers = next(csv_reader)
        print(f"CSV Headers: {headers}")
        
        payloads = []
        row_count = 0
        
        for row in csv_reader:
            if row:  # Skip empty rows
                # Assuming the payload is in the first column or find the appropriate column
                payload = row[0].strip() if row[0] else None
                if payload and payload not in payloads:  # Avoid duplicates
                    payloads.append(payload)
                row_count += 1
        
        print(f"Processed {row_count} rows")
        print(f"Extracted {len(payloads)} unique payloads")
        
        # Save payloads to a JSON file for easy loading
        with open('payloads.json', 'w', encoding='utf-8') as f:
            json.dump(payloads, f, indent=2, ensure_ascii=False)
        
        print("Payloads saved to payloads.json")
        return payloads
        
    except Exception as e:
        print(f"Error fetching CSV: {e}")
        return []

if __name__ == "__main__":
    payloads = fetch_and_process_csv()
    print(f"\nFirst 10 payloads:")
    for i, payload in enumerate(payloads[:10]):
        print(f"{i+1}: {payload}")
