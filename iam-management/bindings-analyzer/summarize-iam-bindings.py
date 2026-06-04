import json
import os

def process_iam_bindings(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    principals_roles = {}
    for bindings_list in data:
        for binding in bindings_list:
            member = binding['member']
            role = binding['role']
            if member not in principals_roles:
                principals_roles[member] = []
            if role not in principals_roles[member]:
                principals_roles[member].append(role)
    return principals_roles

def format_output(principals_roles):
    output_string = ""
    output_string += f"Principal | Roles\n"
    for principal, roles in principals_roles.items():
        principal_type = principal.split(':')[0]
        output_string += f"{principal} | {', '.join(roles)}\n"
    return output_string

# Get local directory path of the script
script_dir = os.path.dirname(os.path.abspath(__file__))
filename = os.path.join(script_dir, "iam-bindings-sample.json")  # Default to local sample file

principals_roles = process_iam_bindings(filename)
if principals_roles:
    formatted_output = format_output(principals_roles)
    print(formatted_output)
