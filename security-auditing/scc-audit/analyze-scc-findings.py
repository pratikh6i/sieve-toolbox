import pandas as pd
import os

csv_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'findingsofssc.csv')
project_col = 'resource.gcp_metadata.project_display_name'
category_col = 'finding.category'

try:
    results_df = (
        pd.read_csv(csv_file_path)
        .groupby([project_col, category_col], observed=False) # Use observed=False if grouping behavior needs consistency across pandas versions
        .size()
        .reset_index(name='Count')
        .rename(columns={project_col: 'Project Name', category_col: 'Finding Category'})
        .sort_values(by=['Project Name', 'Finding Category'])
    )
    if results_df.empty:
         print("No findings data processed.")
    else:
         print(results_df.to_string(index=False))
except FileNotFoundError:
    print(f"Error: File not found at '{csv_file_path}'")
except KeyError as e:
    print(f"Error: Column not found in CSV - {e}. Ensure '{project_col}' and '{category_col}' exist.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
