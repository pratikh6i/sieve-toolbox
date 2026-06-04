#!/usr/bin/env python3

# =====================================================================================
# SCRIPT: IAM AUDIT REPORT GENERATOR
# DESCRIPTION: This script audits a Google Cloud project to generate a CSV report
#              detailing service accounts, their assigned roles, and which of those
#              roles and permissions have been used in the last 90 days.
# REQUIREMENTS: Python 3, google-cloud-asset, google-cloud-recommender, google-cloud-iam
# =====================================================================================

import csv
import subprocess
import sys
from google.cloud import asset_v1
from google.cloud import recommender_v1
from google.cloud import iam_admin_v1
from google.api_core import exceptions

# A global dictionary to act as a cache to avoid repeated API calls.
ROLE_PERMISSIONS_CACHE = {}

# --- AUTHENTICATION & HELPER FUNCTIONS ---

def check_authentication():
    """
    Checks the gcloud authenticated user to ensure the script is running as the intended user.
    This is the most common point of failure for permission errors.
    """
    print("🔐 Step 0: Verifying local gcloud authentication...")
    try:
        # Run the gcloud command to get the currently authenticated account.
        result = subprocess.run(
            ["gcloud", "config", "get-value", "account"],
            capture_output=True,
            text=True,
            check=True
        )
        authed_user = result.stdout.strip()
        if not authed_user:
            print("❌ FATAL ERROR: No authenticated user found by gcloud.")
            print("   Please run 'gcloud auth application-default login' in your terminal.")
            return None
        
        print(f"✅ Script is running as: {authed_user}")
        print("   Please ensure this is the correct user with the required IAM roles on the target project.")
        return authed_user

    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ FATAL ERROR: gcloud CLI command failed or is not installed.")
        print("   Please ensure the Google Cloud SDK is installed and that 'gcloud auth application-default login' has been run.")
        return None


def get_permissions_for_role(role_name):
    """Fetches the list of permissions associated with a specific IAM role using a cache."""
    if role_name in ROLE_PERMISSIONS_CACHE:
        return ROLE_PERMISSIONS_CACHE[role_name]

    print(f"    - Fetching permissions for role: '{role_name}'...")
    try:
        iam_admin_client = iam_admin_v1.IAMClient()
        request = iam_admin_v1.GetRoleRequest(name=role_name)
        role = iam_admin_client.get_role(request=request)
        permissions = role.included_permissions or []
        ROLE_PERMISSIONS_CACHE[role_name] = permissions
        return permissions
    except exceptions.PermissionDenied:
        print(f"    ⚠️  PERMISSION DENIED for role '{role_name}'. Ensure the authenticated user has 'iam.roleViewer' permission.")
    except exceptions.NotFound:
        print(f"    ⚠️  Role '{role_name}' NOT FOUND. It might be a custom role from another project or deleted.")
    except Exception as e:
        print(f"    ⚠️  An unexpected error occurred while fetching role '{role_name}': {e}")
    
    ROLE_PERMISSIONS_CACHE[role_name] = []
    return []

def generate_security_comment(assigned_roles, utilized_roles, used_permissions):
    """Generates an automated security comment based on the roles and permissions."""
    comments = []
    highly_privileged_roles = {
        'roles/owner', 'roles/editor', 'roles/iam.serviceAccountAdmin', 
        'roles/iam.securityAdmin', 'roles/resourcemanager.projectIamAdmin'
    }
    assigned_admin_roles = highly_privileged_roles.intersection(assigned_roles)
    if assigned_admin_roles:
        comments.append(f"High-Privilege roles assigned: {', '.join(assigned_admin_roles)}. Review if necessary.")

    utilized_admin_roles = highly_privileged_roles.intersection(utilized_roles)
    if utilized_admin_roles:
         comments.append(f"Utilized high-privilege roles: {', '.join(utilized_admin_roles)}. Validate usage.")

    if len(assigned_roles) > len(utilized_roles):
        comments.append("Has non-utilized roles which could be removed to reduce privilege.")

    if not used_permissions and assigned_roles:
        comments.append("This service account has assigned roles but shows NO usage in the last 90 days. Candidate for removal.")

    return " ".join(comments) if comments else "Good. Roles appear utilized."


# --- CORE API CALL FUNCTIONS ---

def get_project_iam_policy(project_id, authed_user):
    """Fetches the entire IAM policy for a given project, handling pagination."""
    print(f"\n🔍 Step 1: Fetching IAM policy for project '{project_id}'...")
    all_results = []
    try:
        asset_client = asset_v1.AssetServiceClient()
        scope = f"projects/{project_id}"
        full_resource_name = f"//cloudresourcemanager.googleapis.com/projects/{project_id}"
        request = asset_v1.AnalyzeIamPolicyRequest(
            analysis_query=asset_v1.IamPolicyAnalysisQuery(
                scope=scope,
                resource_selector=asset_v1.IamPolicyAnalysisQuery.ResourceSelector(
                    full_resource_name=full_resource_name
                ),
            ),
        )
        
        # The API response is paginated. This loop iterates through all pages of results.
        for page in asset_client.analyze_iam_policy(request=request).main_analysis.analysis_results:
            all_results.append(page)
        
        print(f"✅ Successfully fetched IAM policy ({len(all_results)} bindings found).")
        return all_results

    except exceptions.PermissionDenied:
        print(f"❌ FATAL ERROR: Permission denied to analyze IAM policy for project '{project_id}'.")
        print(f"   Please ensure the user '{authed_user}' has the 'Cloud Asset Viewer' (roles/cloudasset.viewer) role.")
    except exceptions.NotFound:
        print(f"❌ FATAL ERROR: Project '{project_id}' not found.")
    except Exception as e:
        if "API has not been used" in str(e) or "is not enabled" in str(e):
             print(f"❌ FATAL ERROR: The Cloud Asset API is not enabled for project '{project_id}'.")
             print(f"   Run: gcloud services enable cloudasset.googleapis.com --project {project_id}")
        else:
             print(f"❌ FATAL ERROR: An unexpected error occurred while fetching IAM policy: {e}")
    return None

def get_iam_usage_insights(project_id, authed_user):
    """Fetches IAM usage insights for the last 90 days, handling pagination."""
    print(f"\n🔬 Step 2: Fetching IAM usage insights for project '{project_id}'...")
    all_insights = []
    try:
        recommender_client = recommender_v1.RecommenderClient()
        parent = f"projects/{project_id}/locations/global/insightTypes/google.iam.policy.Insight"
        
        # The API response is paginated. This loop iterates through all pages of results.
        for insight in recommender_client.list_insights(parent=parent):
            all_insights.append(insight)
            
        print(f"✅ Successfully fetched {len(all_insights)} IAM usage insights.")
        return all_insights
    
    except exceptions.PermissionDenied:
        print(f"❌ FATAL ERROR: Permission denied to list IAM insights for project '{project_id}'.")
        print(f"   Please ensure the user '{authed_user}' has the 'Recommender Viewer' (roles/recommender.iamViewer) role.")
    except Exception as e:
        if "API has not been used" in str(e) or "is not enabled" in str(e):
             print(f"❌ FATAL ERROR: The Recommender API is not enabled for project '{project_id}'.")
             print(f"   Run: gcloud services enable recommender.googleapis.com --project {project_id}")
        else:
             print(f"❌ FATAL ERROR: An unexpected error occurred while fetching IAM insights: {e}")
    return None


# --- MAIN EXECUTION LOGIC ---

def main():
    """Main function to orchestrate the entire audit process."""
    authed_user = check_authentication()
    if not authed_user:
        sys.exit(1) # Exit if authentication check fails

    project_id = input("Enter your Google Cloud Project ID: ")
    if not project_id:
        print("Project ID cannot be empty. Exiting.")
        return

    # Step 1: Fetch Data
    iam_policy_results = get_project_iam_policy(project_id, authed_user)
    if iam_policy_results is None: return

    iam_usage_insights = get_iam_usage_insights(project_id, authed_user)
    if iam_usage_insights is None: return

    # Step 2: Process Data
    print("\n🔄 Step 3: Processing and analyzing the collected data...")
    processed_data = {}
    for result in iam_policy_results:
        member = result.iam_binding.member
        if member.startswith("serviceAccount:"):
            sa_email = member.split(':', 1)[1]
            if sa_email not in processed_data:
                processed_data[sa_email] = {"assigned_roles": set(), "used_permissions": set()}
            processed_data[sa_email]["assigned_roles"].add(result.iam_binding.role)
    print(f"   - Found {len(processed_data)} service accounts in the IAM policy.")

    for insight in iam_usage_insights:
        member = insight.content["member"]
        if member in processed_data and "permissions" in insight.content:
            used_perms = {p["permission"] for p in insight.content["permissions"]}
            processed_data[member]["used_permissions"].update(used_perms)

    # Step 3: Generate Report Rows
    print("\n📝 Step 4: Generating the final report...")
    final_report_rows = []
    for sa_email, data in sorted(processed_data.items()):
        assigned_roles = data["assigned_roles"]
        used_permissions = data["used_permissions"]
        
        utilized_roles = {role for role in assigned_roles if not set(get_permissions_for_role(role)).isdisjoint(used_permissions)}
        non_utilized_roles = assigned_roles - utilized_roles
        security_comment = generate_security_comment(assigned_roles, utilized_roles, used_permissions)

        row = {
            "Service Account": sa_email,
            "All Assigned Roles": "\n".join(sorted(list(assigned_roles))),
            "Non-utilized Roles": "\n".join(sorted(list(non_utilized_roles))),
            "Utilized Roles": "\n".join(sorted(list(utilized_roles))),
            "Being Used Permissions": "\n".join(sorted(list(used_permissions))) if used_permissions else "N/A",
            "Security wise Comments": security_comment
        }
        final_report_rows.append(row)

    # Step 4: Write to CSV
    output_filename = f'iam_audit_report_{project_id}.csv'
    fieldnames = ["Service Account", "All Assigned Roles", "Non-utilized Roles", "Utilized Roles", "Being Used Permissions", "Security wise Comments"]
    
    try:
        with open(output_filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(final_report_rows)
        print(f"\n🎉 Success! Report has been generated: {output_filename}")
    except IOError as e:
        print(f"\n❌ FATAL ERROR: Could not write to file '{output_filename}'. Error: {e}")

if __name__ == "__main__":
    main()
