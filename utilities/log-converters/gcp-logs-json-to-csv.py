import json
import csv

def flatten_json(y):
    """
    Helper function to flatten nested JSON.
    Example: {"a": {"b": 1}} becomes {"a.b": 1}
    """
    out = {}

    def flatten(x, name=''):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + '.')
        elif type(x) is list:
            for i, a in enumerate(x):
                flatten(a, name + str(i) + '.')
        else:
            out[name[:-1]] = x

    flatten(y)
    return out

# 1. Load the JSON data
input_filename = 'my_logs.json'  # Change this if needed
output_filename = 'full_logs_flattened.csv'

try:
    with open(input_filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"Loaded {len(data)} log entries.")

    # 2. Flatten every single log entry
    flattened_data = [flatten_json(entry) for entry in data]

    # 3. Dynamic Header Discovery
    # We look at ALL entries to find EVERY unique key present in the file
    all_headers = set()
    for entry in flattened_data:
        all_headers.update(entry.keys())
    
    # Sort headers alphabetically so related fields (like httpRequest.*) stay together
    headers = sorted(list(all_headers))

    print(f"Detected {len(headers)} unique columns. Writing to CSV...")

    # 4. Write to CSV
    with open(output_filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(flattened_data)

    print(f"Success! Created {output_filename}")

except Exception as e:
    print(f"Error: {e}") 
