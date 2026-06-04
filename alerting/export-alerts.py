from google.cloud import monitoring_v3
from google.protobuf.json_format import MessageToDict
import csv

def format_comparison(comp_string):
    """Translates GCP's comparison strings into readable math operators."""
    mapping = {
        "COMPARISON_GT": ">",
        "COMPARISON_LT": "<",
        "COMPARISON_GE": ">=",
        "COMPARISON_LE": "<=",
        "COMPARISON_EQ": "=",
        "COMPARISON_NE": "!=",
    }
    return mapping.get(comp_string, comp_string)

def export_clean_alerts(project_id, output_filename="gcp_alert_policies_audit.csv"):
    client = monitoring_v3.AlertPolicyServiceClient()
    project_name = f"projects/{project_id}"

    print(f"\nFetching alerts for project: {project_id}...")
    
    try:
        policies = client.list_alert_policies(name=project_name)
    except Exception as e:
        print(f"Failed to retrieve alerts. Check Project ID and permissions.\nError: {e}")
        return

    # Highly readable, separated headers
    headers = [
        "Policy Display Name",
        "Status",
        "Condition Name",
        "Condition Type",
        "Filter / Query",
        "Trigger Logic",
        "Duration",
        "Aligner (Per-Series)",
        "Reducer (Cross-Series)",
        "Grouped By",
        "Combiner",
        "Notification Channel IDs",
        "Playbook / Docs",
        "Policy ID",
        "Created On",
        "Last Modified"
    ]

    with open(output_filename, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(headers)

        policy_count = 0
        condition_count = 0

        for policy in policies:
            policy_count += 1
            policy_dict = MessageToDict(policy._pb)

            # 1. Policy Details
            p_display = policy_dict.get('displayName', 'N/A')
            p_enabled = "Enabled" if policy_dict.get('enabled', True) else "Disabled"
            p_combiner = policy_dict.get('combiner', 'N/A')
            
            raw_p_name = policy_dict.get('name', '')
            p_id = raw_p_name.split('/')[-1] if raw_p_name else 'N/A'
            
            # Use commas and newlines so Sheets can wrap them into a vertical list
            raw_channels = policy_dict.get('notificationChannels', [])
            clean_channels = ",\n".join([c.split('/')[-1] for c in raw_channels])
            
            doc = policy_dict.get('documentation', {}).get('content', 'None')
            created = policy_dict.get('creationRecord', {}).get('mutateTime', '')
            modified = policy_dict.get('mutationRecord', {}).get('mutateTime', '')

            # 2. Condition Details
            conditions = policy_dict.get('conditions', [])
            
            for cond in conditions:
                condition_count += 1
                c_display = cond.get('displayName', 'N/A')
                
                c_type = "-"
                c_filter_query = "-"
                c_trigger_logic = "-"
                c_duration = "-"
                a_aligner = "-"
                a_reducer = "-"
                c_group_by = "-"

                if 'conditionThreshold' in cond:
                    c_type = "Metric Threshold"
                    data = cond['conditionThreshold']
                    c_filter_query = data.get('filter', '-')
                    
                    comp = format_comparison(data.get('comparison', ''))
                    val = data.get('thresholdValue', '')
                    c_trigger_logic = f"{comp} {val}".strip()
                    c_duration = data.get('duration', '0s')
                    
                    aggs = data.get('aggregations', [])
                    if aggs:
                        a_aligner = aggs[0].get('perSeriesAligner', '').replace('ALIGN_', '')
                        a_reducer = aggs[0].get('crossSeriesReducer', '').replace('REDUCE_', '') or "-"
                        # Use commas and newlines for clean vertical lists in Sheets
                        c_group_by = ",\n".join(aggs[0].get('groupByFields', [])) or "None"

                elif 'conditionAbsent' in cond:
                    c_type = "Metric Absence"
                    data = cond['conditionAbsent']
                    c_filter_query = data.get('filter', '-')
                    c_trigger_logic = "Missing Data"
                    c_duration = data.get('duration', '0s')
                    
                    aggs = data.get('aggregations', [])
                    if aggs:
                        a_aligner = aggs[0].get('perSeriesAligner', '').replace('ALIGN_', '')
                        c_group_by = ",\n".join(aggs[0].get('groupByFields', [])) or "None"

                elif 'conditionPrometheusQueryLanguage' in cond:
                    c_type = "PromQL"
                    data = cond['conditionPrometheusQueryLanguage']
                    c_filter_query = data.get('query', '').replace('\n', ' ')
                    c_trigger_logic = "Evaluated via Query"
                    c_duration = data.get('duration', '0s')

                elif 'conditionMonitoringQueryLanguage' in cond:
                    c_type = "MQL"
                    data = cond['conditionMonitoringQueryLanguage']
                    c_filter_query = data.get('query', '').replace('\n', ' ')
                    c_trigger_logic = "Evaluated via Query"
                    c_duration = data.get('duration', '0s')

                writer.writerow([
                    p_display, p_enabled, c_display, c_type, c_filter_query,
                    c_trigger_logic, c_duration, a_aligner, a_reducer, c_group_by,
                    p_combiner, clean_channels, doc, p_id, created, modified
                ])

    print(f"\nSuccess! Processed {policy_count} policies containing {condition_count} total conditions.")
    print(f"Data saved neatly to '{output_filename}'")

if __name__ == "__main__":
    project_id_input = input("Please enter your GCP Project ID: ").strip()
    if not project_id_input:
        print("Project ID cannot be blank. Exiting script.")
    else:
        export_clean_alerts(project_id_input)
