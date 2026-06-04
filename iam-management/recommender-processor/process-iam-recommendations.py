import json
import os

def process_iam_bindings(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    principals_actions = {}
    for bindings_list in data:
        for binding in bindings_list:
            member = binding['member']
            role = binding['role']
            action = binding['action']  # Get the action
            if member not in principals_actions:
                principals_actions[member] = {'ADD': [], 'REMOVE': []}
            principals_actions[member][action].append(role)  # Store role by action
    return principals_actions

def format_output(principals_actions):
    output_string = ""
    output_string += f"Principal | Roles to Remove | Roles to Add\n"
    for principal, actions in principals_actions.items():
        remove_roles = ', '.join(actions['REMOVE']) or "None"  # Handle empty lists
        add_roles = ', '.join(actions['ADD']) or "None"
        output_string += f"{principal} | {remove_roles} | {add_roles}\n"
    return output_string

# Get local directory path of the script
script_dir = os.path.dirname(os.path.abspath(__file__))
filename = os.path.join(script_dir, "iam-recommendations-sample.json")  # Default to local sample file

principals_actions = process_iam_bindings(filename)
if principals_actions:
    formatted_output = format_output(principals_actions)
    print(formatted_output)
