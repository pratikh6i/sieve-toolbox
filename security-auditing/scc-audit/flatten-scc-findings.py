import json
import pandas as pd

def flatten_scc_json():
    print("Loading JSON data...")
    with open('all_findings.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    # gcloud outputs a list of dictionaries, where the actual data is inside a 'finding' key
    print(f"Extracting {len(data)} findings...")
    findings_list = [item.get('finding', {}) for item in data]

    # This is the magic command: it automatically flattens nested JSON 
    # (e.g., 'vulnerability.cvssv3.baseScore' becomes its own column)
    print("Flattening data and discovering columns...")
    df = pd.json_normalize(findings_list)

    # Export the massive dataframe to CSV
    output_file = 'scc_all_findings_flattened.csv'
    df.to_csv(output_file, index=False)
    
    print(f"Success! Exported to {output_file}.")
    print(f"Total columns dynamically generated: {len(df.columns)}")

if __name__ == "__main__":
    flatten_scc_json()
