import json
import csv

def process_iam_bindings_csv(filename):
    project_actions = {}

    with open(filename, 'r', encoding='utf-8') as f:
        csv_reader = csv.reader(f)
        
        for row in csv_reader:
            if not row:
                continue 

            # Fix: If the CSV reader lumps the whole line into one column, 
            # we manually split it by the pipe delimiter.
            if len(row) == 1:
                if "|" not in row[0]:
                    continue
                parts = row[0].split("|", 1)
                project_id = parts[0].strip()
                json_string = parts[1].strip()
            elif len(row) >= 2:
                project_id = row[0].strip()
                json_string = row[1].strip()
            else:
                continue

            # Skip the header row
            if "finding.iam_bindings" in json_string or "Project Name" in project_id:
                continue

            if not json_string:
                continue

            if project_id not in project_actions:
                project_actions[project_id] = {}

            try:
                # The csv module still beautifully handles the double quote escaping
                bindings_data = json.loads(json_string)
                
                # Ensure we are iterating through a flat list
                if isinstance(bindings_data, list) and all(isinstance(i, list) for i in bindings_data):
                    items_to_process = [item for sublist in bindings_data for item in sublist]
                else:
                    items_to_process = bindings_data

                for binding in items_to_process:
                    member = binding.get('member')
                    role = binding.get('role')
                    action = binding.get('action')

                    # Skip incomplete bindings
                    if not member or not role or not action:
                        continue

                    if member not in project_actions[project_id]:
                        project_actions[project_id][member] = {'ADD': [], 'REMOVE': []}

                    project_actions[project_id][member][action].append(role)

            except json.JSONDecodeError as e:
                print(f"Warning: Could not parse JSON for project '{project_id}'. Error: {e}")

    return project_actions

def format_output(project_actions):
    output_string = ""
    output_string += "Project ID | Principal | Roles to Remove | Roles to Add\n"
    
    for project_id, principals_actions in project_actions.items():
        for principal, actions in principals_actions.items():
            remove_roles = ', '.join(actions['REMOVE']) or "None"
            add_roles = ', '.join(actions['ADD']) or "None"
            
            output_string += f"{project_id} | {principal} | {remove_roles} | {add_roles}\n"

    return output_string


# --- Execution ---
filename = "/home/pratik_shetti/NTUC/IAM-processor/iam-binding.csv"  

processed_data = process_iam_bindings_csv(filename)

if processed_data:
    formatted_output = format_output(processed_data)
    print(formatted_output)
else:
    # Fail-safe to let you know if parsing failed entirely instead of just returning blank
    print("No data was processed. The script didn't find valid JSON data in the rows.")