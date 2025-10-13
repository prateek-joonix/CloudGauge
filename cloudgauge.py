# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#to rebuild
import os
import requests
import csv
import io
import uuid
import json
import traceback
import concurrent.futures
import logging
import sys
import re
import vertexai
import time
import threading
import random
import glob
from datetime import datetime, timezone, timedelta
from vertexai.generative_models import GenerativeModel
from flask import Flask, Response, request, render_template_string, redirect, url_for, jsonify
import google.auth
import google.auth.transport.requests
from google.auth import default as google_auth_default
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build as google_api_build
from googleapiclient.errors import HttpError
from google.cloud import asset_v1, tasks_v2, storage, recommender_v1
from google.api_core.exceptions import AlreadyExists, PermissionDenied
from google.cloud import osconfig_v1
from google.api_core import exceptions as core_exceptions
from google.cloud.recommender_v1.types import Insight

# --- Global Configuration ---
# Configures logging to display INFO level messages with a timestamp.
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: [%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


# --- Flask App Initialization & Configuration ---
app = Flask(__name__)

# --- Environment Variables & Constants ---
GCS_PUBLIC_URL = "https://raw.githubusercontent.com/GoogleCloudPlatform/CloudGauge/Beta/assets/gcp_best_practices.csv"
SCOPES = ['https://www.googleapis.com/auth/cloud-platform']
PROJECT_ID = os.environ.get('PROJECT_ID')
LOCATION = os.environ.get('LOCATION')
TASK_QUEUE = os.environ.get('TASK_QUEUE')
RESULTS_BUCKET = os.environ.get('RESULTS_BUCKET')
SA_EMAIL = os.environ.get('SERVICE_ACCOUNT_EMAIL')

def _get_self_url():
    """
    (NEW) Dynamically discovers the public URL of the Cloud Run service itself.
    This avoids the need to manually set WORKER_URL during deployment.
    """
    # Cloud Run automatically injects the K_SERVICE environment variable
    service_name = os.environ.get('K_SERVICE')
    if not service_name:
        raise RuntimeError("K_SERVICE environment variable not found. Cannot auto-discover URL. Please set WORKER_URL manually.")

    print(f"🚀 Auto-discovering URL for service: {service_name}...")
    try:
        credentials, _ = google_auth_default(scopes=SCOPES)
        # Use the Cloud Run Admin API
        run_service = google_api_build('run', 'v1', credentials=credentials)
        
        service_path = f"projects/{PROJECT_ID}/locations/{LOCATION}/services/{service_name}"
        
        request = run_service.projects().locations().services().get(name=service_path)
        response = request.execute()
        
        url = response.get('status', {}).get('url')
        if not url:
            raise RuntimeError(f"Could not find URL in API response for service {service_name}.")
        
        print(f"✅ Auto-discovered WORKER_URL: {url}")
        return url
    except Exception as e:
        logging.critical(f"FATAL: Could not discover WORKER_URL via API. Ensure the 'Cloud Run Admin API' is enabled. Error: {e}")
        raise
    
WORKER_URL = _get_self_url()

# ---Add a startup check for essential environment variables ---
def check_environment_variables():
    """Checks for required environment variables at startup."""
    required_vars = ['PROJECT_ID', 'LOCATION', 'TASK_QUEUE', 'RESULTS_BUCKET', 'SERVICE_ACCOUNT_EMAIL']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    if missing_vars:
        error_message = f"FATAL: Missing required environment variables: {', '.join(missing_vars)}"
        logging.critical(error_message)
        # In a production environment, you might want to raise an exception or exit
        # For Cloud Run, this will make the deployment fail with a clear log message
        raise RuntimeError(error_message)
    else:
        print("✅ All required environment variables are set.")

check_environment_variables()

# --- GCP Service Clients (Initialized once for efficiency) ---
tasks_client = tasks_v2.CloudTasksClient()
storage_client = storage.Client()

# --- Startup Functions ---

def create_task_queue_if_not_exists():
    """
    Verifies the existence of the required Cloud Tasks queue upon application startup.
    If the queue does not exist, it creates it. This function is essential for
    the asynchronous task processing of the application.
    """
    print("🚀 Checking for Cloud Tasks queue...")
    logging.info("🚀 Initializing startup checks: Verifying Cloud Tasks queue...")
    LOCATION = os.environ.get('LOCATION')
    if not LOCATION:
        logging.critical("FATAL: Location environment variable not found.")
        raise RuntimeError("Location environment variable is not available.")
    logging.info(f"✅ Detected Cloud Run region: {LOCATION}")
    try:
        parent = f"projects/{PROJECT_ID}/locations/{LOCATION}"
        queue_name = f"{parent}/queues/{TASK_QUEUE}"
        tasks_client.create_queue(parent=parent, queue={"name": queue_name})
        logging.info(f"✅ Successfully created Cloud Tasks queue '{TASK_QUEUE}' in '{LOCATION}'.")
    except AlreadyExists:
        logging.info(f"✅ Cloud Tasks queue '{TASK_QUEUE}' already exists. No action needed.")
    except PermissionDenied as e:
        logging.critical(f"FATAL: PERMISSION DENIED. The service account '{SA_EMAIL}' is likely missing the 'Cloud Tasks Admin' role.")
        raise
    except Exception as e:
        logging.critical(f"FATAL: An unexpected error occurred during startup task queue checks: {e}")
        raise

# Initialize task queue if environment variables are set.
if PROJECT_ID and TASK_QUEUE:
    create_task_queue_if_not_exists()
else:
    print("⚠️ PROJECT_ID or TASK_QUEUE environment variables not set. Skipping queue creation.")

# --- Helper Functions for Streaming Architecture ---
def _write_finding_to_gcs(job_id, check_name, finding_data):
    """Uploads a single finding record as a JSON object to GCS."""
    try:
        bucket = storage_client.bucket(RESULTS_BUCKET)
        # Use a unique name for each finding to prevent overwrites
        blob_name = f"intermediate/{job_id}/{check_name}_{uuid.uuid4()}.json"
        blob = bucket.blob(blob_name)
        blob.upload_from_string(
            json.dumps(finding_data),
            content_type='application/json'
        )
    except Exception as e:
        logging.error(f"Failed to write finding to GCS for {check_name}: {e}")

def _read_all_findings_from_gcs(job_id):
    """Reads all temporary finding files for a job and groups them by category."""
    category_map = {
        # Security & Identity
        "Critical Org-Level Roles": "Security & Identity", "Public Org-Level Access": "Security & Identity",
        "Organization IAM Policy": "Security & Identity", "Security Command Center Status": "Security & Identity",
        "Project IAM Hygiene": "Security & Identity", "Service Account Key Rotation": "Security & Identity",
        "Public GCS Buckets": "Security & Identity", "Open Firewall Rules": "Security & Identity",
        "Primitive Roles (Owner or Editor)": "Security & Identity",

        # Cost Optimization
        "Idle Cloud SQL Instances": "Cost Optimization", "Low Utilization VMs": "Cost Optimization",
        "VM Rightsizing": "Cost Optimization", "Unassociated IPs": "Cost Optimization",
        "Idle Load Balancers": "Cost Optimization", "Idle Persistent Disks": "Cost Optimization",
        "Underutilized Reservations": "Cost Optimization", "Idle Reservations": "Cost Optimization",

        # Reliability & Resilience
        "Cloud Storage Versioning": "Reliability & Resilience", "GKE Hygiene": "Reliability & Resilience",
        "Essential Contacts": "Reliability & Resilience", "Personalized Service Health": "Reliability & Resilience",
        "Cloud SQL High Availability": "Reliability & Resilience", "Cloud SQL Automated Backups": "Reliability & Resilience",
        "Cloud SQL Backup Retention": "Reliability & Resilience", "Cloud SQL PITR": "Reliability & Resilience",
        "MIG Resilience (Zonal)": "Reliability & Resilience", "Disk Snapshot Resilience": "Reliability & Resilience",

        # Operational Excellence & Observability
        "Organization Log Sink": "Operational Excellence & Observability",
        "OS Config Agent Coverage": "Operational Excellence & Observability", "Monitoring Alert Coverage": "Operational Excellence & Observability",
        "Standalone VMs (Not in MIGs)": "Operational Excellence & Observability",
        "VPC IP Address Utilization": "Operational Excellence & Observability", "VPC Connectivity": "Operational Excellence & Observability",
        "Load Balancer Health": "Operational Excellence & Observability", "GKE IP Address Utilization": "Operational Excellence & Observability",
        "GKE Connectivity": "Operational Excellence & Observability", "GKE Service Account": "Operational Excellence & Observability",
        "Dynamic Route Health": "Operational Excellence & Observability", "Cloud SQL Connectivity": "Operational Excellence & Observability",
        "VPC Firewall Complexity (>150 Rules)": "Operational Excellence & Observability",
        "Recent Changes (Org & Project)": "Operational Excellence & Observability", "Unattended Projects": "Operational Excellence & Observability",
        "Quota Utilization (>80%)": "Operational Excellence & Observability"
    }
    categorized_results = {cat: [] for cat in set(category_map.values())}
    
    try:
        bucket = storage_client.bucket(RESULTS_BUCKET)
        prefix = f"intermediate/{job_id}/"
        blobs = bucket.list_blobs(prefix=prefix)

        for blob in blobs:
            # Skip the org policy files
            if "best_practices.json" in blob.name or "current_policies.json" in blob.name:
                continue
            
            try:
                data_string = blob.download_as_text()
                data = json.loads(data_string)
                # The check name is stored inside the JSON object itself
                check_name = data.get("Check")
                category = category_map.get(check_name)
                if category:
                    categorized_results[category].append(data)
            except Exception as e:
                logging.error(f"Failed to read and process GCS finding {blob.name}: {e}")
    except Exception as e:
        logging.error(f"Failed to list findings from GCS for job {job_id}: {e}")
        
    return categorized_results

def _write_org_policies_to_gcs(job_id, best_practices, current_policies):
    """Writes the raw org policy data to JSON files in GCS."""
    try:
        bucket = storage_client.bucket(RESULTS_BUCKET)
        
        bp_blob = bucket.blob(f"intermediate/{job_id}/best_practices.json")
        bp_blob.upload_from_string(json.dumps(best_practices), content_type='application/json')
        
        cp_blob = bucket.blob(f"intermediate/{job_id}/current_policies.json")
        cp_blob.upload_from_string(json.dumps(current_policies), content_type='application/json')
    except Exception as e:
        logging.error(f"Failed to write org policy files to GCS: {e}")

def _read_org_policies_from_gcs(job_id):
    """Reads the raw org policy data from GCS files."""
    try:
        bucket = storage_client.bucket(RESULTS_BUCKET)
        
        bp_blob = bucket.blob(f"intermediate/{job_id}/best_practices.json")
        best_practices = json.loads(bp_blob.download_as_text())
        
        cp_blob = bucket.blob(f"intermediate/{job_id}/current_policies.json")
        current_policies = json.loads(cp_blob.download_as_text())
        
        return (best_practices, current_policies)
    except Exception as e:
        logging.error(f"Failed to read org policy files from GCS: {e}")
        return (None, None)

# --- Core Data Fetching and Analysis Functions ---

def find_col_index(header_map, possible_names):
    """
    Helper function to find the index of a column from a list of possible names.
    This provides flexibility when parsing CSV files with slightly different headers.

    Args:
        header_map (dict): A dictionary mapping lowercase header names to their indices.
        possible_names (list): A list of possible header names to search for.

    Returns:
        int: The index of the first matching column found.

    Raises:
        KeyError: If none of the possible column names are found in the header map.
    """
    for name in possible_names:
        if name in header_map:
            return header_map[name]
    raise KeyError(f"Could not find any of the required columns: {possible_names}")

def get_best_practices_from_gcs(public_url):
    """
    Downloads and parses a CSV file of GCP best practices from a public GCS URL.
    It categorizes boolean organization policies to be used for compliance checking.

    Args:
        public_url (str): The public URL to the best practices CSV file.

    Returns:
        dict: A dictionary of best practices grouped by category.
        str: An error message if the download or parsing fails.
    """
    print("⬇️  Downloading best practices...")
    try:
        response = requests.get(public_url)
        response.raise_for_status()
        reader = csv.reader(response.text.splitlines())
        header_map = {h.strip().lower(): i for i, h in enumerate(next(reader))}
        
        id_col = find_col_index(header_map, ['id', 'constraint'])
        name_col = find_col_index(header_map, ['display name', 'policy', 'policy name', 'name', 'policy display name', 'displayname'])
        rec_col = find_col_index(header_map, ['recommended to set *'])

        best_practices_by_category = {}
        current_category = "Uncategorized"
        policies_added = 0 

        for row in reader:
            if len([c for c in row if c.strip()]) == 1:
                current_category = row[0].strip()
                if current_category not in best_practices_by_category:
                    best_practices_by_category[current_category] = []
                continue
                
            if len(row) > max(id_col, name_col, rec_col) and row[id_col].strip():
                
                
                recommendation_text = row[rec_col].strip().lower()
                expected_value = None

                if "should have" in recommendation_text or "must have" in recommendation_text or "could have" in recommendation_text:
                    expected_value = "True"
                elif "wont have" in recommendation_text:
                    expected_value = "False"
                
                # We still use "is not None" to correctly include policies that are "False"
                if expected_value is not None:
                    if current_category not in best_practices_by_category: 
                        best_practices_by_category[current_category] = []
                    
                    best_practices_by_category[current_category].append({
                        "policyId": row[id_col].strip(), 
                        "displayName": row[name_col].strip(), 
                        "expectedValue": expected_value
                    })
                    policies_added += 1
                

        print(f"✅ CSV parsing complete. Loaded {policies_added} boolean policies into the checker.")
        return best_practices_by_category
        
    except Exception as e:
        return f"Error downloading or parsing CSV: {e}"
    
def get_effective_org_policies(scope, scope_id):
    """
    Calculates the effective organization policies for a resource by manually
    traversing its ancestry and merging policies. This avoids the low daily
    quota of the Cloud Asset Policy Analyzer API.

    Args:
        scope (str): The scope ('organization', 'folder', 'project').
        scope_id (str): The ID of the resource.

    Returns:
        dict: A dictionary of effective organization policies, keyed by policy ID.
        str: An error message if fetching fails.
    """
    print(f"🔍 Calculating effective policies for {scope} '{scope_id}' by traversing hierarchy...")
    try:
        credentials, _ = google_auth_default(scopes=SCOPES)
        # Main client remains v1 for compatibility with listOrgPolicies
        crm_service = google_api_build('cloudresourcemanager', 'v1', credentials=credentials)

        # --- START OF MODIFICATION ---
        # Initialize a separate v3 client specifically to bypass the v1 'get' bug for folder
        crm_v3_service = google_api_build('cloudresourcemanager', 'v3', credentials=credentials)
        # --- END OF MODIFICATION ---

        def list_policies_for_resource(resource_str):
            """Helper to fetch and format policies for a given resource string."""
            policies = {}
            try:
                api_call = lambda: crm_service.organizations().listOrgPolicies(resource=resource_str, body={}).execute() if resource_str.startswith('organizations/') else \
                                 crm_service.folders().listOrgPolicies(resource=resource_str, body={}).execute() if resource_str.startswith('folders/') else \
                                 crm_service.projects().listOrgPolicies(resource=resource_str, body={}).execute()
                response = _call_api_with_backoff(api_call, context_message=f"listOrgPolicies for {resource_str}")
                for policy in response.get('policies', []):
                    if full_path := policy.get('constraint'):
                        policies[full_path.split('/')[-1]] = policy
            except Exception as e:
                logging.warning(f"Could not list policies for {resource_str}: {e}")
            return policies

        effective_policies = {}
        resource_hierarchy = []

        if scope == 'organization':
            resource_hierarchy.append(f"organizations/{scope_id}")
        elif scope == 'project':
            ancestry = crm_service.projects().getAncestry(projectId=scope_id, body={}).execute()
            for ancestor in ancestry.get('ancestor', []):
                resource_hierarchy.append(f"{ancestor['resourceId']['type']}s/{ancestor['resourceId']['id']}")
            resource_hierarchy.append(f"projects/{scope_id}")
        elif scope == 'folder':
            ancestors = []
            curr_folder = f"folders/{scope_id}"
            while curr_folder:
                ancestors.append(curr_folder)
                # --- THIS IS CHANGE FOR FOLDER FIX ---
                # Use the new v3 client for the 'get' call, which does not have the bug
                folder_details = crm_v3_service.folders().get(name=curr_folder).execute()
                # --- END OF CHANGE ---
                parent = folder_details.get('parent')
                if parent and parent.startswith('organizations/'):
                    ancestors.append(parent)
                    break
                curr_folder = parent
            resource_hierarchy = list(reversed(ancestors))

        if not resource_hierarchy:
            return f"Could not determine hierarchy for {scope} {scope_id}"

        print(f"   -> Traversing hierarchy: {' -> '.join(resource_hierarchy)}")
        for resource_str in resource_hierarchy:
            policies_at_level = list_policies_for_resource(resource_str)
            effective_policies.update(policies_at_level)

        print(f"✅ Successfully calculated {len(effective_policies)} effective policies.")
        return effective_policies

    except Exception as e:
        traceback.print_exc()
        return f"A critical error occurred in get_effective_org_policies: {e}"
    
def list_projects_for_scope(scope, scope_id):
    """
    Retrieves a list of all ACTIVE projects within a given scope (org, folder, or project)
    using the recursive Cloud Asset Inventory API for complete coverage.
    """
    print(f"📋 Listing projects for {scope} '{scope_id}' using Cloud Asset Inventory...")

    # The single-project case remains the fastest method for that specific scope.
    if scope == 'project':
        try:
            credentials, _ = google_auth_default(scopes=SCOPES)
            service = google_api_build('cloudresourcemanager', 'v1', credentials=credentials)
            project = service.projects().get(projectId=scope_id).execute()
            if project.get('lifecycleState') == 'ACTIVE':
                print(f"✅ Found 1 ACTIVE project.")
                # Return in the same format as the Asset API for consistency
                return [{'projectId': project['projectId'], 'displayName': project.get('name', project['projectId'])}]
            else:
                print("⚠️ Project is not ACTIVE.")
                return []
        except Exception as e:
            print(f"❌ Error fetching single project: {e}")
            return []

    # --- NEW RECURSIVE LOGIC USING CLOUD ASSET API ---
    try:
        asset_client = asset_v1.AssetServiceClient()

        # Define the parent scope for the asset search
        parent_scope_map = {
            'organization': f'organizations/{scope_id}',
            'folder': f'folders/{scope_id}'
        }
        asset_search_scope = parent_scope_map.get(scope)
        if not asset_search_scope:
            print(f"❌ Invalid scope '{scope}' provided for asset search.")
            return []

        # Perform a single, recursive search for all projects
        response = asset_client.search_all_resources(
            request={
                "scope": asset_search_scope,
                "asset_types": ["cloudresourcemanager.googleapis.com/Project"],
                "query": "state:ACTIVE", # Filter for active projects at the API level
            }
        )

        # Process the results into the expected format
        all_projects = []
        for resource in response:
            # The project ID is part of the full resource name
            project_id = resource.name.split('/')[-1]
            all_projects.append({
                'projectId': project_id,
                'displayName': resource.display_name
            })
        
        print(f"✅ Found {len(all_projects)} ACTIVE projects recursively.")
        return all_projects

    except Exception as e:
        logging.error(f"❌ Critical error listing projects with Cloud Asset API: {e}")
        traceback.print_exc()
        return []
    
def get_active_compute_locations(all_projects):
    """
    Discovers active GCP zones and regions by scanning for various compute resources
    across all projects in the organization. This helps focus subsequent checks
    on relevant locations.

    Args:
        org_id (str): The ID of the organization.
        all_projects (list): A list of project dictionaries.

    Returns:
        tuple: A tuple containing two lists: (active_zones, active_regions).
    """
    print("📍 Discovering active compute zones and regions...")
    active_zones, active_regions = set(), set()

    def scan_project(project):
        project_id = project['projectId']
        try:
            credentials, _ = google_auth_default(scopes=SCOPES)
            compute = google_api_build('compute', 'v1', credentials=credentials)
            
            # Method 1: Discover zones from VM instances AND infer their regions
            req = compute.instances().aggregatedList(project=project_id)
            while req:
                resp = req.execute()
                for scope, result in resp.get('items', {}).items():
                    if scope.startswith('zones/') and result.get('instances'):
                        zone = scope.split('/')[-1]
                        active_zones.add(zone)
                        # Your suggestion: Infer region from zone (e.g., 'us-central1-a' -> 'us-central1')
                        active_regions.add('-'.join(zone.split('-')[:-1]))
                req = compute.instances().aggregatedList_next(previous_request=req, previous_response=resp)

            # Method 2: Discover regions from reserved IP Addresses (your suggestion)
            req = compute.addresses().aggregatedList(project=project_id)
            while req:
                resp = req.execute()
                for scope, result in resp.get('items', {}).items():
                    if scope.startswith('regions/') and result.get('addresses'):
                        active_regions.add(scope.split('/')[-1])
                req = compute.addresses().aggregatedList_next(previous_request=req, previous_response=resp)

            # Method 3: Discover regions from Forwarding Rules (Load Balancers)
            req = compute.forwardingRules().aggregatedList(project=project_id)
            while req:
                resp = req.execute()
                for scope, result in resp.get('items', {}).items():
                    if scope.startswith('regions/') and result.get('forwardingRules'):
                        active_regions.add(scope.split('/')[-1])
                req = compute.forwardingRules().aggregatedList_next(previous_request=req, previous_response=resp)

        except Exception as e:
            logging.warning(f"Could not scan locations for project {project_id}: {e}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(scan_project, all_projects)

    # Add 'global' as it's a valid location for some recommenders
    active_regions.add('global')
    
    print(f"✅ Discovered {len(active_zones)} active zones and {len(active_regions)} active regions.")
    return list(active_zones), list(active_regions)

def _get_parent_org():
    """Finds the parent organization of the current project."""
    try:
        credentials, _ = google_auth_default(scopes=SCOPES)
        service = google_api_build('cloudresourcemanager', 'v1', credentials=credentials)
        ancestry = service.projects().getAncestry(projectId=PROJECT_ID, body={}).execute()
        for resource in ancestry.get('ancestor', []):
            if resource.get('resourceId', {}).get('type') == 'organization':
                return resource['resourceId']['id']
    except Exception as e:
        print(f"⚠️ Could not automatically determine organization ID: {e}")
    return None

@app.route('/api/list-resources')
def list_resources():
    """API endpoint to list resources based on scope (org, folder, project)."""
    scope = request.args.get('scope')
    if not scope:
        return jsonify({"error": "Scope parameter is required"}), 400

    org_id = _get_parent_org()
    if not org_id:
        return jsonify({"error": "Could not determine parent organization"}), 500

    resources = []
    try:
        asset_client = asset_v1.AssetServiceClient()
        parent_scope = f"organizations/{org_id}"

        if scope == 'organization':
            resources.append({"id": org_id, "name": f"Organization {org_id}"})
            return jsonify(resources)

        asset_type_map = {
            'folder': 'cloudresourcemanager.googleapis.com/Folder',
            'project': 'cloudresourcemanager.googleapis.com/Project'
        }
        
        asset_type = asset_type_map.get(scope)
        if not asset_type:
            return jsonify({"error": "Invalid scope"}), 400

        print(f"🔍 Searching for assets of type '{asset_type}' under organization '{org_id}'...")
        response = asset_client.search_all_resources(
            request={
                "scope": parent_scope,
                "asset_types": [asset_type],
            }
        )
        
        for resource in response:
            display_name = resource.display_name
            if scope == 'project':
                # For projects, the name is the project ID
                project_id = resource.name.split('/')[-1]
                resources.append({"id": project_id, "name": f"{display_name} ({project_id})"})
            else: # For folders
                folder_id = resource.name.split('/')[-1]
                resources.append({"id": folder_id, "name": f"{display_name}"})
        
        # Sort resources by name
        resources.sort(key=lambda x: x['name'])
        print(f"✅ Found {len(resources)} resources.")
        return jsonify(resources)

    except Exception as e:
        print(f"❌ Error listing resources: {e}")
        traceback.print_exc()
        return jsonify({"error": f"Failed to list resources: {e}"}), 500

# --- Helper function for backoff ---

def _call_api_with_backoff(api_call_func, context_message="API call"):
    """
    Wraps a Google Cloud API list call with exponential backoff to handle 429 rate limit errors.

    Args:
        api_call_func: A lambda or function that executes the actual API call
                       (e.g., lambda: client.list_recommendations(parent=parent)).

    Returns:
        The results of the API call, or an empty list if all retries fail.
    """
    max_retries = 5
    initial_delay = 1.5  # seconds
    backoff_factor = 2

    for attempt in range(max_retries):
        try:
            # Execute the provided API call function
            return api_call_func()
        except core_exceptions.ResourceExhausted as e:
            # This is the specific exception for 429 errors from google-api-core
            if attempt < max_retries - 1:
                # Calculate wait time with exponential backoff and random jitter
                delay = (initial_delay * (backoff_factor ** attempt)) + random.uniform(0, 1)
                logging.warning(
                    f"Rate limit hit (429) for for {context_message}. Retrying in {delay:.2f} seconds... (Attempt {attempt + 1}/{max_retries})"
                )
                time.sleep(delay)
            else:
                logging.error(f"API rate limit exceeded for {context_message} after {max_retries} attempts. Error: {e}")
                return [] # Return empty list after final failure
        except Exception as e:
            # For any other error, don't retry, just log it and move on.
            logging.error(f"An unexpected API error occurred for {context_message}: {e}")
            return []
    return [] # Should not be reached, but as a fallback

# --- Security & Identity Checks ---

def check_org_iam_policy(org_id, job_id):
    """
    Checks the organization-level IAM policy for critical and public role bindings.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries.
    """
    CHECK_NAME_CRITICAL = "Critical Org-Level Roles"
    CHECK_NAME_PUBLIC = "Public Org-Level Access"
    print(f"🕵️  [{job_id}] Checking for {CHECK_NAME_CRITICAL} and {CHECK_NAME_PUBLIC}...")

    try:
        credentials, _ = google_auth_default(scopes=SCOPES)
        service = google_api_build('cloudresourcemanager', 'v1', credentials=credentials)
        policy = service.organizations().getIamPolicy(resource=f'organizations/{org_id}', body={}).execute()
        
        critical_roles = ['roles/owner', 'roles/resourcemanager.organizationAdmin']
        public_principals = ['allUsers', 'allAuthenticatedUsers']

        # --- Check 1: Critical Org-Level Roles ---
        crit_role_findings = [{"Role": b.get('role'), "Principal": m} 
                              for b in policy.get('bindings', []) 
                              if b.get('role') in critical_roles 
                              for m in b.get('members', [])]
        
        if crit_role_findings:
            result_crit = {"Check": CHECK_NAME_CRITICAL, "Finding": crit_role_findings, "Status": "Action Required"}
        else:
            result_crit = {"Check": CHECK_NAME_CRITICAL, "Finding": [{"Status": "No principals found with Owner or Org Admin roles."}], "Status": "Compliant"}
        _write_finding_to_gcs(job_id, CHECK_NAME_CRITICAL.replace(" ", "_"), result_crit)

        # --- Check 2: Public Org-Level Access ---
        public_access_findings = [{"Role": b.get('role'), "Principal": m} 
                                  for b in policy.get('bindings', []) 
                                  for m in b.get('members', []) 
                                  if m in public_principals]
        
        if public_access_findings:
            result_public = {"Check": CHECK_NAME_PUBLIC, "Finding": public_access_findings, "Status": "Action Required"}
        else:
            result_public = {"Check": CHECK_NAME_PUBLIC, "Finding": [{"Status": "No public access found at the organization level."}], "Status": "Compliant"}
        _write_finding_to_gcs(job_id, CHECK_NAME_PUBLIC.replace(" ", "_"), result_public)

    except Exception as e:
        # If the entire check fails, write a single error file.
        error_result = {"Check": "Organization IAM Policy Check", "Finding": [{"Error": str(e)}], "Status": "Error"}
        _write_finding_to_gcs(job_id, "Organization_IAM_Policy_Check_Error", error_result)

def check_audit_logging(org_id, job_id):
    """
    Verifies if an organization-level log sink is configured for centralized audit logging.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries.
    """
    CHECK_NAME = "Organization Log Sink"
    print(f"📜 [{job_id}] Checking for {CHECK_NAME}...")
    try:
        credentials, _ = google_auth_default(scopes=SCOPES)
        service = google_api_build('logging', 'v2', credentials=credentials)
        sinks = service.organizations().sinks().list(parent=f'organizations/{org_id}').execute().get('sinks', [])
        if sinks:
            finding_data = [{"Sink Name": s['name'], "Destination": s['destination']} for s in sinks]
            result = {"Check": CHECK_NAME, "Finding": finding_data, "Status": "Compliant"}
        else:
            result = {"Check": CHECK_NAME, "Finding": [{"Issue": "No organization-level log sink configured."}], "Status": "Action Required"}
    except Exception as e:
        result = {"Check": "Log Sink Check", "Finding": [{"Error": str(e)}], "Status": "Error"}
    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)

def check_scc_status(org_id, job_id):
    """
    Checks the status and tier of Security Command Center (SCC) for the organization.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries. Recommends 'PREMIUM' tier.
    """
    CHECK_NAME = "Security Command Center Status"
    print(f"🛡️  [{job_id}] Checking {CHECK_NAME}...")
    try:
        credentials, _ = google_auth_default(scopes=SCOPES)
        service = google_api_build('securitycenter', 'v1', credentials=credentials)
        settings = service.organizations().getOrganizationSettings(name=f"organizations/{org_id}/organizationSettings").execute()
        tier = settings.get('tier', 'STANDARD')
        status = "Compliant" if tier == "PREMIUM" else "Action Required"
        finding = {"Tier": tier, "Recommendation": "Premium tier provides advanced threat detection." if status == "Action Required" else "N/A"}
        result = {"Check": "Security Command Center", "Finding": [finding], "Status": status}
    except HttpError as e:
        if "API has not been used" in str(e) or e.resp.status == 404:
            result = {"Check": "Security Command Center", "Finding": [{"Issue": "Security Command Center is not enabled for this organization."}], "Status": "Action Required"}
        else:
            result = {"Check": "Security Command Center", "Finding": [{"Error": str(e)}], "Status": "Error"}
    except Exception as e:
        result = {"Check": "Security Command Center", "Finding": [{"Error": str(e)}], "Status": "Error"}
    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)

def check_service_health_status(org_id, job_id):
    """
    Verifies if the Personalized Service Health API is enabled and accessible.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries indicating the status.
    """
    CHECK_NAME = "Personalized Service Health"
    print(f"❤️‍🩹 [{job_id}] Checking {CHECK_NAME}...")
    try:
        credentials, _ = google_auth_default(scopes=SCOPES)
        credentials.refresh(GoogleAuthRequest())
        headers = {"Authorization": f"Bearer {credentials.token}"}
        url = f"https://servicehealth.googleapis.com/v1beta/organizations/{org_id}/locations/global/organizationEvents?filter=state=ACTIVE%20category=INCIDENT"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = {"Check": CHECK_NAME, "Finding": [{"Status": "Enabled"}], "Status": "Compliant"}
        elif response.status_code == 403:
            error = response.json().get('error', {}).get('message', 'Permission denied.')
            result = {"Check": CHECK_NAME, "Finding": [{"Error": error}], "Status": "Error"}
        else:
            response.raise_for_status()
            result = {"Check": CHECK_NAME, "Finding": [{"Status": "Enabled"}], "Status": "Compliant"} # Should not be reached on error
    except Exception as e:
        result = {"Check": CHECK_NAME, "Finding": [{"Error": str(e)}], "Status": "Error"}
    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_essential_contacts(org_id, job_id):
    """
    Checks if Essential Contacts are configured for key notification categories.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries indicating missing contact categories.
    """
    CHECK_NAME = "Essential Contacts"
    print(f"📞 [{job_id}] Checking for {CHECK_NAME}...")
    try:
        credentials, _ = google_auth_default(scopes=SCOPES)
        service = google_api_build('essentialcontacts', 'v1', credentials=credentials)
        contacts = service.organizations().contacts().list(parent=f"organizations/{org_id}").execute().get('contacts', [])
        found = {c.get('notificationCategorySubscriptions', [])[0] for c in contacts if c.get('notificationCategorySubscriptions')}
        missing = sorted(list({"SECURITY", "TECHNICAL", "LEGAL"} - found))
        
        if not missing:
            result = {"Check": CHECK_NAME, "Finding": [{"Status": "All key contact categories are configured."}], "Status": "Compliant"}
        else:
            result = {"Check": CHECK_NAME, "Finding": [{"Missing Categories": ", ".join(missing)}], "Status": "Action Required"}
    except HttpError as e:
        if "API has not been used" in str(e) or "service is disabled" in str(e):
             result = {"Check": CHECK_NAME, "Finding": [{"Error": "The Essential Contacts API is not enabled. Please enable it to run this check."}], "Status": "Error"}
        else:
            result = {"Check": CHECK_NAME, "Finding": [{"Error": str(e)}], "Status": "Error"}
    except Exception as e:
        result = {"Check": CHECK_NAME, "Finding": [{"Error": str(e)}], "Status": "Error"}
    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_project_iam_policy(scope_id, projects, job_id):
    """
    Scans all projects in parallel for the use of primitive roles (Owner/Editor).

    Args:
        org_id (str): The organization ID.
        projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries detailing primitive role usage.
    """
    CHECK_NAME = "Primitive Roles (Owner or Editor)"
    print(f"🕵️  [{job_id}] Checking for {CHECK_NAME} in parallel...")
    if not projects: 
        result = {"Check": "Project IAM Hygiene", "Finding": [{"Error": "Could not list projects."}], "Status": "Error"}
        _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)
        return
    
    def check_single_project(p):
        project_id, findings = p['projectId'], []
        try:
            credentials, _ = google_auth_default(scopes=SCOPES)
            service = google_api_build('cloudresourcemanager', 'v1', credentials=credentials)
            policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            for b in policy.get('bindings', []):
                if b.get('role') in ['roles/owner', 'roles/editor']:
                    for member in b.get('members', []):
                        findings.append({'Project': project_id, 'Principal': member, 'Role': b.get('role')})
        except Exception as e: logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return findings

    all_findings = []
    for project in projects:
        all_findings.extend(check_single_project(project))
    
    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No projects found with Owner or Editor roles."}], "Status": "Compliant"}
    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)

def check_os_config_coverage(scope_id, all_projects, job_id):
    """
    Checks VM instances across all projects to identify those not reporting to OS Config.
    This helps ensure patch management and inventory visibility. Excludes GKE and Dataproc VMs.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries listing VMs without OS Config agent coverage.
    """
    CHECK_NAME = "OS Config Agent Coverage"
    print(f"🤖 [{job_id}] Checking for {CHECK_NAME} in parallel...")
    if not all_projects: return []

    def check_single_project(project):
        project_id = project['projectId']
        try:
            credentials, _ = google_auth_default(scopes=SCOPES)
            compute = google_api_build('compute', 'v1', credentials=credentials)
            osconfig = osconfig_v1.OsConfigZonalServiceClient()
            vms, req = [], compute.instances().aggregatedList(project=project_id, filter='status = "RUNNING"')
            while req:
                resp = req.execute(); req = compute.instances().aggregatedList_next(previous_request=req, previous_response=resp)
                for res in resp.get('items', {}).values():
                    if 'instances' in res: vms.extend(res['instances'])
            if not vms: return None

            # --- FIX: Added a filter to exclude Dataproc VMs by label ---
            missing = [
                vm['name'] for vm in vms
                if not vm['name'].startswith('gke-')
                and 'goog-dataproc-cluster-name' not in vm.get('labels', {})
                and not any(item.get('key') == 'gke-cluster-name' for item in vm.get('metadata', {}).get('items', []))
                and not _is_os_reporting(osconfig, project_id, vm)
            ]

            if missing: return {"Project": project_id, "VMs Not Reporting": ", ".join(sorted(missing))}
        except core_exceptions.FailedPrecondition:
            return {"Project": project_id, "Issue": "OS inventory management disabled."}
        except Exception as e: logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return None

    def _is_os_reporting(client, project, vm):
        try:
            path = f"projects/{project}/locations/{vm['zone'].split('/')[-1]}/instances/{vm['name']}/inventory"
            client.get_inventory(request={"name": path})
            return True
        except core_exceptions.NotFound:
            return False
        except Exception:
            return False

    results = []
    for project in all_projects:
        # check_single_project returns a single dictionary or None
        finding = check_single_project(project)
        if finding:
            # We append the single dictionary to our list of results
            results.append(finding)

    if not results:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "All unmanaged VMs appear to have OS Config agent."}], "Status": "Compliant"}
    else:
        result = {"Check": CHECK_NAME, "Finding": results, "Status": "Action Required"}
    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)


def check_monitoring_coverage(scope_id, all_projects, job_id):
    """
    Scans projects for key monitoring alert policies (e.g., for Cloud SQL, GKE, Quotas).

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for projects missing essential alerts.
    """
    CHECK_NAME = "Monitoring Alert Coverage"
    print(f"📊 [{job_id}] Checking {CHECK_NAME} in parallel...")
    if not all_projects: return []
    
    def check_project(project):
        project_id, issues = project['projectId'], []
        try:
            credentials, _ = google_auth_default(scopes=SCOPES)
            monitor = google_api_build('monitoring', 'v3', credentials=credentials)
            asset = asset_v1.AssetServiceClient(credentials=credentials)
            policies = monitor.projects().alertPolicies().list(name=f"projects/{project_id}").execute().get('alertPolicies', [])
            filters = " ".join(c.get('conditionThreshold', {}).get('filter', '') for p in policies for c in p.get('conditions', [])).lower()
            
            asset_map = {'sqladmin.googleapis.com/Instance': 'Cloud SQL', 'container.googleapis.com/Cluster': 'GKE Cluster', 'compute.googleapis.com/ForwardingRule': 'Load Balancer'}
            for asset_type, name in asset_map.items():
                if list(asset.list_assets(request={"parent": f"projects/{project_id}", "asset_types": [asset_type]})) and name.lower().replace(" ", "_") not in filters:
                    issues.append({"Project": project_id, "Issue": f"Missing alert policy for {name}"})
            if "serviceruntime.googleapis.com/quota" not in filters:
                issues.append({"Project": project_id, "Issue": "Missing Quota alerting policy"})
        except Exception as e: logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return issues
        
    results = []
    for project in all_projects:
        # check_project returns a list of findings for the project
        findings = check_project(project)
        if findings:
            # We extend the main results list with the items from the findings list
            results.extend(findings)

    if not results:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "All projects appear to have key alert policies."}], "Status": "Compliant"}
    else:
        result = {"Check": CHECK_NAME, "Finding": results, "Status": "Action Required"}
    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)


def run_network_insights(scope_id, all_projects, active_zones, active_regions, job_id):
    """
    Fetches and parses Network Analyzer insights across all projects.
    Normalizes various insight types into a consistent, table-friendly format.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.
        active_zones (list): A list of active GCP zones.
        active_regions (list): A list of active GCP regions.

    Returns:
        list: A list of finding dictionaries, grouped by insight type.
    """
    print("🌐 Performing Network Insights checks (Final Normalized Parser)...")
    if not all_projects: return []
    
    all_locations = active_zones + active_regions

    # --- THIS HELPER FUNCTION DOES ALL THE PARSING ---
    def _parse_network_insight_content(insight_dict, description, project_id, check_name):
        """
        Helper to parse raw insight data into a structured dictionary. This version includes
        the corrected logic for extracting the GKE cluster name for serviceAccountInsight.
        """
        parsed_findings_list = []
        content_dict = insight_dict.get('content', {})
        
        if check_name == "GKE Service Account":
            resource_name = "N/A"  # Default value

            # Method 1 (Most Reliable): Use the specific, nested clusterUri from your log data.
            try:
                # Path: content -> nodeServiceAccountInsight -> clusterUri
                cluster_uri = content_dict.get('nodeServiceAccountInsight', {}).get('clusterUri')
                if cluster_uri and isinstance(cluster_uri, str):
                    resource_name = cluster_uri.split('/')[-1]
            except Exception:
                pass # Failsafe

            # Method 2 (Excellent Fallback): Use the top-level 'target_resources' field.
            if resource_name == "N/A":
                target_resources = insight_dict.get('target_resources', [])
                if target_resources and isinstance(target_resources[0], str):
                    resource_name = target_resources[0].split('/')[-1]

            # Method 3 (Final Fallback): Regex on the description string.
            if resource_name == "N/A":
                match = re.search(r"GKE cluster '([^']+)'", description)
                if match:
                    resource_name = match.group(1)

            # Append the finding once, after all attempts are complete.
            parsed_findings_list.append({
                "Project": project_id,
                "Finding Type": "GKE Service Account",
                "Resource": f"Cluster: {resource_name}",
                "Detail": description,
                "Value": "Compute Engine default service account"
            })

    # --- END OF GKE PARSER ---

        # --- END OF MODIFICATION ---
        
        # --- EXISTING PARSERS FOR OTHER INSIGHT TYPES ---
        elif 'Utilization' in check_name:
            # For Subnet IP Utilization
            if 'ipUtilizationSummaryInfo' in content_dict:
                for info in content_dict.get('ipUtilizationSummaryInfo', []):
                    for net_stat in info.get('networkStats', []):
                        network = net_stat.get('networkUri', 'N/A').split('/')[-1]
                        for sub_stat in net_stat.get('subnetStats', []):
                            subnet = sub_stat.get('subnetUri', 'N/A').split('/')[-1]
                            for range_stat in sub_stat.get('subnetRangeStats', []):
                                parsed_findings_list.append({
                                    "Project": project_id,
                                    "Finding Type": "Subnet Utilization",
                                    "Resource": f"Subnet: {subnet} (Network: {network})",
                                    "Detail": f"Range: {range_stat.get('subnetRangePrefix', 'N/A')}",
                                    "Value": f"{range_stat.get('allocationRatio', 0) * 100:.2f}% Allocation"
                                })
                
            # For PSA IP Utilization
            if 'psaIpUtilizationSummaryInfo' in content_dict:
                for info in content_dict.get('psaIpUtilizationSummaryInfo', []):
                    for net_stat in info.get('networkStats', []):
                        network = net_stat.get('networkUri', 'N/A').split('/')[-1]
                        for psa_stat in net_stat.get('psaStats', []):
                            parsed_findings_list.append({
                                "Project": project_id,
                                "Finding Type": "PSA Utilization",
                                "Resource": f"Network: {network}",
                                "Detail": f"PSA Range: {psa_stat.get('psaRangePrefix', 'N/A')}",
                                "Value": f"{psa_stat.get('allocationRatio', 0) * 100:.2f}% Allocation"
                            })

            # For GKE IP Utilization
            if 'gkeIpUtilizationSummaryInfo' in content_dict:
                for info in content_dict.get('gkeIpUtilizationSummaryInfo', []):
                    for cluster_stat in info.get('clusterStats', []):
                        parsed_findings_list.append({
                            "Project": project_id,
                            "Finding Type": "GKE Utilization",
                            "Resource": f"Cluster: {cluster_stat.get('clusterUri', 'N/A').split('/')[-1]}",
                            "Detail": f"Pod Range Usage: {cluster_stat.get('podRangesAllocationRatio', 0) * 100:.2f}%",
                            "Value": f"Service Range Usage: {cluster_stat.get('serviceRangesAllocationRatio', 0) * 100:.2f}%"
                        })

            # For Unassigned External IPs
            if 'overallStats' in content_dict:
                stats = content_dict['overallStats']
                parsed_findings_list.append({
                        "Project": project_id,
                        "Finding Type": "Unassigned IPs",
                        "Resource": "Organization (Overall)",
                        "Detail": f"Total Reserved: {stats.get('reservedCount', 0):.0f}",
                        "Value": f"Unassigned Count: {stats.get('unassignedCount', 0):.0f} ({stats.get('unassignedRatio', 0) * 100:.2f}%)"
                })

        # --- Fallback for any other insight types remains the same ---
        if not parsed_findings_list:
            # This block now also handles cases where an error might occur in a specific parser
            parsed_findings_list.append({
                "Project": project_id,
                "Finding Type": "General Insight",
                "Resource": description,
                "Detail": "(No structured data)",
                "Value": "See finding"
            })
            
        return parsed_findings_list
    

    insight_type_map = {
        "VPC IP Address Utilization": "google.networkanalyzer.vpcnetwork.ipAddressInsight",
        "VPC Connectivity": "google.networkanalyzer.vpcnetwork.connectivityInsight",
        "Load Balancer Health": "google.networkanalyzer.networkservices.loadBalancerInsight",
        "GKE IP Address Utilization": "google.networkanalyzer.container.ipAddressInsight",
        "GKE Connectivity": "google.networkanalyzer.container.connectivityInsight",
        "GKE Service Account": "google.networkanalyzer.container.serviceAccountInsight",
        "Dynamic Route Health": "google.networkanalyzer.hybridconnectivity.dynamicRouteInsight",
        "Cloud SQL Connectivity": "google.networkanalyzer.managedservices.cloudSqlInsight",
    }

    def check_project(project):
        project_id = project['projectId']
        project_findings_map = {} 
        try:
            client = recommender_v1.RecommenderClient()
            for loc in all_locations:
                for check_name, insight_type_id in insight_type_map.items(): 
                    parent = f"projects/{project_id}/locations/{loc}/insightTypes/{insight_type_id}"
                    try:
                        api_call = lambda: client.list_insights(parent=parent)
                        context = f"'{check_name}' in {project_id} at {loc}"
                        for insight in _call_api_with_backoff(api_call,context_message=context):
                            parsed_data_list = []
                            try:
                                insight_dict = Insight.to_dict(insight)
                                
                                # --- MODIFIED CALL ---
                                # Pass the check_name INTO the parser so it knows what it's parsing.
                                parsed_data_list = _parse_network_insight_content(insight_dict, insight.description, project_id, check_name)

                            except Exception as e:
                                parsed_data_list = [{"Project": project_id, "Finding Type": "Top-level Parse Error", "Resource": insight.description, "Detail": str(e), "Value": "N/A"}]
                            
                            if check_name not in project_findings_map:
                                project_findings_map[check_name] = []

                            project_findings_map[check_name].extend(parsed_data_list)
                            
                    except Exception:
                        pass 
        except Exception as e:
            logging.warning(f"Could not check network insights for {project_id}: {e}")
        return project_findings_map
        

    project_results_list = []
    for project in all_projects:
        project_results_list.append(check_project(project))

    
    # Aggregate results from all projects
    final_findings_by_check = {}
    for project_map in project_results_list:
        for check_name, findings in project_map.items():
            if check_name not in final_findings_by_check:
                final_findings_by_check[check_name] = []
            final_findings_by_check[check_name].extend(findings)


    # Write one file per insight type
    for check_name, all_findings in final_findings_by_check.items():
        if all_findings:
            result = {"Check": check_name, "Finding": all_findings, "Status": "Action Required"}
            _write_finding_to_gcs(job_id, check_name.replace(" ", "_"), result)

    
def check_sa_key_rotation(scope_id, all_projects, job_id):
    """
    Scans ALL projects and ALL service account keys for user-managed keys older than 90 days.
    This version corrects the pagination logic for listing keys.
    """
    CHECK_NAME = "Service Account Key Rotation"
    print(f"🔑 [{job_id}] Checking for {CHECK_NAME}...")

    all_findings = []

    for project in all_projects:
        project_id = project['projectId']
        try:
            credentials, _ = google_auth_default(scopes=SCOPES)
            iam_service = google_api_build('iam', 'v1', credentials=credentials)

            # This pagination loop for service accounts is correct and remains unchanged.
            s_accounts = []
            request = iam_service.projects().serviceAccounts().list(name=f'projects/{project_id}')
            while request:
                response = request.execute()
                s_accounts.extend(response.get('accounts', []))
                request = iam_service.projects().serviceAccounts().list_next(previous_request=request, previous_response=response)

            for sa in s_accounts:
                keys = []
                # --- CORRECTED: Start of manual pagination for keys ---
                # Make the initial request to list keys
                key_request = iam_service.projects().serviceAccounts().keys().list(name=sa['name'], keyTypes=['USER_MANAGED'])

                # Loop until there are no more pages
                while True:
                    key_response = key_request.execute()
                    keys.extend(key_response.get('keys', []))
                    
                    next_page_token = key_response.get('nextPageToken')
                    if next_page_token:
                        # If a next page token exists, prepare the next request
                        key_request = iam_service.projects().serviceAccounts().keys().list(
                            name=sa['name'],
                            keyTypes=['USER_MANAGED'],
                            pageToken=next_page_token
                        )
                    else:
                        # If there's no token, we've retrieved all keys, so break the loop
                        break
                # --- END of corrected manual pagination ---

                for key in keys:
                    created_time = datetime.fromisoformat(key['validAfterTime'].replace('Z', '+00:00'))
                    if (datetime.now(timezone.utc) - created_time).days > 90:
                        all_findings.append({
                            "Project": project_id,
                            "Service Account": sa['email'],
                            "Issue": f"Key is older than 90 days (created {created_time.strftime('%Y-%m-%d')})."
                        })

        except Exception as e:
            logging.error(f"Failed SA key check for project {project_id}: {e}")
            all_findings.append({
                "Project": project_id,
                "Service Account": "N/A",
                "Issue": f"Error scanning project for SA keys: {e}"
            })

    # Final reporting logic remains the same.
    if all_findings:
        result = {
            "Check": CHECK_NAME,
            "Finding": all_findings,
            "Status": "Action Required"
        }
    else:
        result = {
            "Check": CHECK_NAME,
            "Finding": [{"Status": "No user-managed service account keys older than 90 days were found."}],
            "Status": "Compliant"
        }

    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)

def check_public_buckets(scope_id, all_projects, job_id):
    """Scans for public GCS buckets and writes findings to a temp file."""
    """
     Scans all projects for Cloud Storage buckets that are publicly accessible.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for any public buckets found.
    """
    CHECK_NAME = "Public GCS Buckets"
    print(f"🪣 [{job_id}] Checking for {CHECK_NAME}...")
    
    def check_project(p):
        project_id, findings = p['projectId'], []
        try:
            # Using a project-specific client can be more reliable at scale
            storage_client_local = storage.Client(project=project_id)
            for bucket in storage_client_local.list_buckets():
                policy = bucket.get_iam_policy(requested_policy_version=3)
                for binding in policy.bindings:
                    if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
                        findings.append({"Project": project_id, "Bucket": bucket.name, "Issue": f"Publicly accessible via role {binding['role']}."})
                        break # No need to check other bindings for this bucket
        except Exception:
            pass # Silently fail for projects where API is disabled or permissions lack
        return findings

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No publicly accessible buckets found."}], "Status": "Compliant"}
    
    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)

def check_organization_policies(scope, scope_id, job_id):
    """Fetches Org Policies and writes the raw data to temp files."""
    CHECK_NAME = "Organization_Policies_Data"
    print(f"📜 [{job_id}] Checking for {CHECK_NAME}...")
    best_practices = get_best_practices_from_gcs(GCS_PUBLIC_URL)
    
   
    # Call the function that manually traverses the hierarchy
    current_policies = get_effective_org_policies(scope, scope_id)
    
    
    if isinstance(best_practices, dict) and isinstance(current_policies, dict):
        _write_org_policies_to_gcs(job_id, best_practices, current_policies)
    else:
        err_msg = f"Best practices error: {best_practices}" if not isinstance(best_practices, dict) else f"Policies error: {current_policies}"
        result = {"Check": "Organization Policies", "Finding": [{"Error": f"Could not fetch policy data for {scope} '{scope_id}'. Details: {err_msg}"}], "Status": "Error"}
        _write_finding_to_gcs(job_id, "Organization_Policies_Check", result)

def check_storage_versioning(scope_id, all_projects, job_id):
    """
    Checks if Object Versioning is enabled on all Cloud Storage buckets.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for buckets without versioning.
    """
    CHECK_NAME = "Cloud Storage Versioning"
    print(f"🔄 [{job_id}] Checking for {CHECK_NAME}...")

    def check_project(p):
        project_id, findings = p['projectId'], []
        try:
            storage_client = storage.Client(project=project_id)
            for bucket in storage_client.list_buckets():
                if not bucket.versioning_enabled:
                    findings.append({"Project": project_id, "Bucket": bucket.name, "Issue": "Object versioning is not enabled."})
        except Exception as e: logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return findings

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "Object versioning is enabled on all buckets."}], "Status": "Compliant"}
    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)

def check_standalone_vms(scope_id, all_projects, job_id):
    """
    Identifies standalone VMs that are not managed by a Managed Instance Group (MIG).
    Excludes GKE and Dataproc VMs.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for standalone VMs.
    """
    CHECK_NAME = "Standalone VMs (Not in MIGs)"
    print(f"🖥️  [{job_id}] Checking for {CHECK_NAME}...")

    def check_project(p):
        project_id = p['projectId']
        try:
            credentials, _ = google_auth_default(scopes=SCOPES)
            compute = google_api_build('compute', 'v1', credentials=credentials)
            vms, req = [], compute.instances().aggregatedList(project=project_id, filter='status = "RUNNING"')
            while req:
                resp = req.execute(); req = compute.instances().aggregatedList_next(previous_request=req, previous_response=resp)
                for res in resp.get('items', {}).values():
                    if 'instances' in res: vms.extend(res['instances'])

            # --- FIX: Added a filter to exclude Dataproc VMs by label and GKE by name ---
            standalone = [
                vm['name'] for vm in vms
                if not any(item.get('key') == 'created-by' for item in vm.get('metadata', {}).get('items', []))
                and not vm['name'].startswith('gke-')
                and 'goog-dataproc-cluster-name' not in vm.get('labels', {})
            ]
            
            if standalone:
                return {"Project": project_id, "Standalone VMs": ", ".join(sorted(standalone))}
        except Exception as e: logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return None

    all_findings = []
    for project in all_projects:
        finding = check_project(project)
        if finding:
            all_findings.append(finding)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Investigation Recommended"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No running standalone, unmanaged VMs found."}], "Status": "Compliant"}
    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)

def check_open_firewall_rules(scope_id, all_projects, job_id):
    """
    Scans all projects for VPC firewall rules open to the internet (0.0.0.0/0).

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for open firewall rules.
    """
    CHECK_NAME = "Open Firewall Rules"
    print(f"🔥 [{job_id}] Checking for Open Firewall Rules in parallel...")
    
    def check_project(p):
        project_id, open_rules = p['projectId'], []
        try:
            credentials, _ = google_auth_default(scopes=SCOPES)
            compute = google_api_build('compute', 'v1', credentials=credentials)
            for rule in compute.firewalls().list(project=project_id).execute().get('items', []):
                if not rule.get('disabled', False) and '0.0.0.0/0' in rule.get('sourceRanges', []):
                    open_rules.append({"Project": project_id, "Rule Name": rule['name'], "VPC": rule['network'].split('/')[-1]})
        except Exception as e: logging.warning(f"Could not check {CHECK_NAME} for {project_id}: {e}")
        return open_rules

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No firewall rules found open to 0.0.0.0/0."}], "Status": "Compliant"}
    _write_finding_to_gcs(job_id, "Open_Firewall_Rules", result) # Using a simplified filename

def check_gke_hygiene(scope_id, all_projects, job_id):
    """
    Checks GKE clusters for best practices like using release channels and auto-upgrades.
    Also fetches active recommendations for the clusters.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for GKE hygiene issues.
    """
    CHECK_NAME = "GKE Hygiene"
    print(f"🚢 [{job_id}] Checking {CHECK_NAME} in parallel...")
    
    def check_project(p):
        project_id, issues = p['projectId'], []
        try:
            credentials, _ = google_auth_default(scopes=SCOPES)
            container = google_api_build('container', 'v1', credentials=credentials)
            recommender = google_api_build('recommender', 'v1', credentials=credentials)
            
            for cluster in container.projects().locations().clusters().list(parent=f"projects/{project_id}/locations/-").execute().get('clusters', []):
                name, location = cluster.get('name'), cluster.get('location')

                if not cluster.get('releaseChannel'):
                    issues.append({"Project": project_id, "Cluster": name, "Issue": "Not on a release channel."})
                
                for pool in cluster.get('nodePools', []):
                    if not pool.get('management', {}).get('autoUpgrade', False):
                        issues.append({"Project": project_id, "Cluster": name, "Node Pool": pool.get('name'), "Issue": "Auto-upgrades disabled."})

                
                reco_parent = f"projects/{project_id}/locations/{location}/recommenders/google.container.DiagnosisRecommender"
                reco_req = recommender.projects().locations().recommenders().recommendations().list(parent=reco_parent, filter='stateInfo.state="ACTIVE"')
                for reco in reco_req.execute().get('recommendations', []):
                    issues.append({"Project": project_id, "Cluster": name, "Recommendation": reco.get('description')})
        except Exception as e:
            logging.warning(f"Could not check GKE hygiene for {project_id}: {e}")
        return issues

    all_findings = []
    for project in all_projects:
        findings = check_project(project)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    else:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "All checked GKE clusters seem to follow best practices."}], "Status": "Compliant"}
    _write_finding_to_gcs(job_id, CHECK_NAME.replace(" ", "_"), result)

def check_resilience_assets(org_id, job_id):
    """
    Checks organization-wide assets for resilience best practices, including
    Cloud SQL HA, backups, MIGs, and disk snapshot storage redundancy.

    Args:
        org_id (str): The organization ID.

    Returns:
        list: A list of finding dictionaries for resilience issues.
    """
    print("🏗️  Checking resilience assets (SQL, MIGs, Snapshots)...")
    all_findings = []
    
    def get_project_from_asset_name(asset_name):
        parts = asset_name.split('/'); return parts[parts.index('projects') + 1] if 'projects' in parts else 'unknown'

    try:
        credentials, _ = google_auth_default(scopes=SCOPES)
        asset_client = asset_v1.AssetServiceClient(credentials=credentials)
        parent = f"organizations/{org_id}"

        # Cloud SQL Checks
        sql_req = {"parent": parent, "asset_types": ["sqladmin.googleapis.com/Instance"], "content_type": asset_v1.ContentType.RESOURCE}
        non_ha, no_backup, bad_retention, no_pitr = [], [], [], []
        for asset in asset_client.list_assets(request=sql_req):
            s, name, proj = asset.resource.data.get("settings", {}), asset.resource.data.get('name'), get_project_from_asset_name(asset.name)
            if s.get("availabilityType") == "ZONAL": non_ha.append({"Project": proj, "Instance": name})
            backup_conf = s.get("backupConfiguration", {})
            if not backup_conf.get("enabled"): no_backup.append({"Project": proj, "Instance": name})
            elif not backup_conf.get("pointInTimeRecoveryEnabled"): no_pitr.append({"Project": proj, "Instance": name})
            if backup_conf.get("retainedBackupsCount", 0) < 30 : bad_retention.append({"Project": proj, "Instance": name, "Retention": backup_conf.get("retainedBackupsCount", "N/A")})

        if non_ha:
            _write_finding_to_gcs(job_id, "Cloud_SQL_High_Availability", {"Check": "Cloud SQL High Availability", "Finding": non_ha, "Status": "Action Required"})
        if no_backup:
            _write_finding_to_gcs(job_id, "Cloud_SQL_Automated_Backups", {"Check": "Cloud SQL Automated Backups", "Finding": no_backup, "Status": "Action Required"})
        if bad_retention:
            _write_finding_to_gcs(job_id, "Cloud_SQL_Backup_Retention", {"Check": "Cloud SQL Backup Retention", "Finding": bad_retention, "Status": "Action Required"})
        if no_pitr:
            _write_finding_to_gcs(job_id, "Cloud_SQL_PITR", {"Check": "Cloud SQL PITR", "Finding": no_pitr, "Status": "Action Required"})

        # Zonal MIGs Check
        mig_req = {"parent": parent, "asset_types": ["compute.googleapis.com/InstanceGroupManager"], "content_type": asset_v1.ContentType.RESOURCE}
        zonal_migs = [{"Project": get_project_from_asset_name(a.name), "MIG Name": a.resource.data.get('name')} for a in asset_client.list_assets(request=mig_req) if 'zone' in a.resource.data and not a.resource.data.get('name', '').startswith('gke-')]
        if zonal_migs:
            _write_finding_to_gcs(job_id, "MIG_Resilience_(Zonal)", {"Check": "MIG Resilience (Zonal)", "Finding": zonal_migs, "Status": "Action Required"})
        
        # Disk Snapshots Check
        snap_req = {"parent": parent, "asset_types": ["compute.googleapis.com/Snapshot"], "content_type": asset_v1.ContentType.RESOURCE}
        single_region = len([a for a in asset_client.list_assets(request=snap_req) if len(a.resource.data.get("storageLocations", [])) <= 1])
        if single_region > 0:
            _write_finding_to_gcs(job_id, "Disk_Snapshot_Resilience", {"Check": "Disk Snapshot Resilience", "Finding": [{"Issue": f"Found {single_region} snapshots stored in only one region."}], "Status": "Action Required"})

    except Exception as e:
        error_result = {"Check": "Resilience Asset Checks", "Finding": [{"Error": str(e)}], "Status": "Error"}
        _write_finding_to_gcs(job_id, "Resilience_Asset_Checks_Error", error_result)

# --- Cost Optimization Checks ---

def run_cost_recommendations(scope_id, all_projects, active_zones, active_regions, job_id):
    """
    Fetches cost-saving recommendations from the Recommender API for all projects.
    Covers idle resources, rightsizing, and underutilized reservations.

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.
        active_zones (list): A list of active GCP zones.
        active_regions (list): A list of active GCP regions.

    Returns:
        list: A list of finding dictionaries detailing cost recommendations.
    """
    print("💰 Performing Cost Recommendation checks in parallel...")
    if not all_projects: return []
    
    #active_zones, active_regions = get_active_compute_locations(org_id, all_projects)

    def _parse_recommendation_safely(reco, project_id):
        """Safely parses a recommendation proto to extract resource name and savings."""
        resource_name = "N/A"
        cost_savings = "N/A"
        
        try:
            # Attempt to get resource name from various possible fields
            if hasattr(reco.content, 'overview'):
                overview_struct = reco.content.overview 
                if 'resourceName' in overview_struct:
                    resource_name = overview_struct['resourceName']
                elif 'resource' in overview_struct:
                    resource_name = overview_struct['resource'].split('/')[-1]

        
            if resource_name == "N/A":
                if (hasattr(reco.content, 'operation_groups') and 
                    reco.content.operation_groups and 
                    reco.content.operation_groups[0].operations and
                    reco.content.operation_groups[0].operations[0].resource):
                    
                    # Get the full resource path, e.g., //compute.googleapis.com/.../disks/disk-1
                    full_resource_path = reco.content.operation_groups[0].operations[0].resource
                    resource_name = full_resource_path.split('/')[-1]

            # If both fail, check targetResources (camelCase, for Reservations etc.) ---
            if resource_name == "N/A":
                if hasattr(reco, 'targetResources') and reco.targetResources:
                    target_list = reco.targetResources
                    if target_list and isinstance(target_list[0], str):
                        resource_name = target_list[0].split('/')[-1]

        except Exception as e:
            logging.warning(f"Failed to parse resource name for {reco.name}: {e}")
            pass # If any error, resource_name remains "N/A"

        # Safely get cost savings
        try:
            cost = reco.primary_impact.cost_projection.cost
            savings_value = -cost.units - (cost.nanos / 1e9)
            cost_savings = f"{savings_value:,.2f} {cost.currency_code}"
        except AttributeError:
            pass

        # Build the final description string
        detail = reco.description
        if "CHANGE_MACHINE_TYPE" in reco.recommender_subtype:
            detail = f"For VM '{resource_name}', {reco.description}"
            
        return {
            "Project": project_id, 
            "Resource Name": resource_name,  # This column should now populate correctly
            "Recommendation": detail, 
            "Est. Monthly Saving": cost_savings
        }

    def check_project(project):
        project_id = project['projectId']
        findings_map = {}
        recommender_map = {
            "Idle Cloud SQL Instances": ("google.cloudsql.instance.IdleRecommender", "region"),
            "Low Utilization VMs": ("google.compute.instance.IdleResourceRecommender", "zone"),
            "VM Rightsizing": ("google.compute.instance.MachineTypeRecommender", "zone"),
            "Unassociated IPs": ("google.compute.address.IdleResourceRecommender", "region"),
            "Idle Load Balancers": ("google.compute.loadBalancer.IdleResourceRecommender", "region"),
            "Idle Persistent Disks": ("google.compute.disk.IdleResourceRecommender", "zone"),
            "Underutilized Reservations": ("google.compute.RightSizeResourceRecommender", "zone"),
            "Idle Reservations": ("google.compute.IdleResourceRecommender", "zone"),
        }
        try:
            client = recommender_v1.RecommenderClient()
            for check, (rec_id, loc_type) in recommender_map.items():
                locations = active_zones if loc_type == "zone" else active_regions
                for loc in locations:
                    if loc_type in ['region', 'zone'] and loc == 'global':
                        continue
                    parent = f"projects/{project_id}/locations/{loc}/recommenders/{rec_id}"
                    try:
                        api_call = lambda: client.list_recommendations(parent=parent)
                        context = f"'{check}' in {project_id} at {loc}"
                        for reco in _call_api_with_backoff(api_call, context_message=context):
                            finding = _parse_recommendation_safely(reco, project_id)
                            if check not in findings_map:
                                findings_map[check] = []
                            findings_map[check].append(finding)
                    except (PermissionDenied, core_exceptions.FailedPrecondition):
                        logging.warning(f"Skipping '{check}' for {project_id} in {loc} due to permissions or disabled API.")
                        break 
                    except Exception as e:
                        logging.error(f"An unexpected API error occurred (or parser failed) for '{check}' in {project_id} at {loc}: {e}")
        except Exception as e:
            logging.error(f"CRITICAL: Cost check failed for project {project_id}. Error: {e}")
        
        return findings_map

    project_results_list = []
    for project in all_projects:
        project_results_list.append(check_project(project))
    
    final_findings_by_check = {}
    for project_map in project_results_list:
        for check_name, findings in project_map.items():
            if check_name not in final_findings_by_check:
                final_findings_by_check[check_name] = []
            final_findings_by_check[check_name].extend(findings)

    for check_name, all_findings in final_findings_by_check.items():
        if all_findings:
            result = {"Check": check_name, "Finding": all_findings, "Status": "Action Required"}
            # Use the check_name as the unique identifier for the filename
            _write_finding_to_gcs(job_id, check_name.replace(" ", "_"), result)

# --- Operational Excellence Checks ---

def run_miscellaneous_checks_refactored(scope, scope_id, all_projects, job_id):
    """
    Runs a series of miscellaneous operational checks, such as firewall complexity,
    recent changes, and unattended projects, respecting the scan scope.
    """
    print("🔍 Performing Miscellaneous checks...")
    if not all_projects:
        return []

    # Initialize lists to hold structured data for each finding type
    firewall_findings = []
    recent_change_findings = []
    unattended_findings = []


    # --- Check 1: Firewall Rules (Runs for all scopes) ---
    def check_firewall_rules_count(project):
        project_id = project['projectId']
        try:
            credentials, _ = google_auth_default(scopes=SCOPES)
            compute_service = google_api_build('compute', 'v1', credentials=credentials)
            rules = compute_service.firewalls().list(project=project_id).execute().get('items', [])
            if len(rules) > 150:
                return {"Project": project_id, "Rule Count": len(rules), "Recommendation": f"Project has {len(rules)} firewall rules."}
        except Exception as e: logging.warning(f"Could not check firewall_rule_count for {project_id}: {e}")
        return None

    firewall_findings = []
    for project in all_projects:
        finding = check_firewall_rules_count(project)
        if finding:
            firewall_findings.append(finding)

    if firewall_findings:
        result = {"Check": "VPC Firewall Complexity (>150 Rules)", "Finding": firewall_findings, "Status": "Investigation Recommended"}
        _write_finding_to_gcs(job_id, "VPC_Firewall_Complexity", result)

    # --- Org-Level Recommender/Insight Checks (Run ONLY for organization scope) ---
    if scope == 'organization':
        print("   -> Checking for organization-level insights...")
        try:
            recommender_client = recommender_v1.RecommenderClient()
            
            # Check for Org-Level Recent Changes
            parent_recent = f"organizations/{scope_id}/locations/global/insightTypes/google.cloud.RecentChangeInsight"
            api_call_recent = lambda: recommender_client.list_insights(parent=parent_recent)
            for insight in _call_api_with_backoff(api_call_recent, context_message="Org-Level Recent Changes"):
                recent_change_findings.append({
                    "Project": f"Org-Level ({scope_id})",
                    "Insight": insight.description
                })

            # Check for Unattended Project Recommendations
            parent_unattended = f"organizations/{scope_id}/locations/global/recommenders/google.resourcemanager.projectUtilization.Recommender"
            api_call_unattended = lambda: recommender_client.list_recommendations(parent=parent_unattended)
            for reco in _call_api_with_backoff(api_call_unattended, context_message="Unattended Projects"):
                project_id_from_reco = "Unknown"
                # Method 1: Try the structured targetResources field (camelCase)
                if hasattr(reco, 'targetResources') and reco.targetResources:
                    project_id_from_reco = reco.targetResources[0].split('/')[-1]

                # Method 2: Try the operation_groups field (snake_case)
                elif (hasattr(reco.content, 'operation_groups') and reco.content.operation_groups and
                      reco.content.operation_groups[0].operations and reco.content.operation_groups[0].operations[0].resource):
                    project_id_from_reco = reco.content.operation_groups[0].operations[0].resource.split('/')[-1]

                # Method 3: As a final fallback, parse the description string
                elif reco.description:
                    match = re.search(r"Project `([^`]+)`", reco.description)
                    if match:
                        project_id_from_reco = match.group(1)
                        
                unattended_findings.append({"Project": project_id_from_reco, "Recommendation": reco.description})
        except Exception as e:
            # Add a single error message if the org-level API calls fail
            error_finding = {"Project": scope_id, "Insight": f"Could not retrieve organization-level insights. Error: {e}"}
            recent_change_findings.append(error_finding)
            unattended_findings.append(error_finding)


    # --- Project-Level Recent Changes Check (Runs for all scopes) ---
    print("   -> Checking for project-level recent changes...")
    def check_project_for_iam_changes(project):
        project_id = project['projectId']
        project_findings_list = []
        try:
            recommender_client = recommender_v1.RecommenderClient()
            parent = f"projects/{project_id}/locations/global/insightTypes/google.cloud.RecentChangeInsight"
            insights = recommender_client.list_insights(parent=parent)
            for insight in insights:
                project_findings_list.append({
                    "Project": project_id,
                    "Insight": insight.description
                })
        except Exception:
            pass 
        return project_findings_list

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_project_for_iam_changes, all_projects)
        for res_list in results:
            recent_change_findings.extend(res_list)

    # --- Final Assembly ---
    if recent_change_findings:
        result = {"Check": "Recent Changes (Org & Project)", "Finding": recent_change_findings, "Status": "Informational"}
        _write_finding_to_gcs(job_id, "Recent_Changes", result)
    
    if unattended_findings:
        result = {"Check": "Unattended Projects", "Finding": unattended_findings, "Status": "Action Required"}
        _write_finding_to_gcs(job_id, "Unattended_Projects", result)

    print("✅ Miscellaneous checks complete.")



def run_service_limit_checks_refactored(scope_id, all_projects, job_id):
    """
    Checks regional compute quotas for all projects to identify any approaching their limit (>80%).

    Args:
        org_id (str): The organization ID.
        all_projects (list): A list of project dictionaries.

    Returns:
        list: A list of finding dictionaries for quotas with high utilization.
    """
    CHECK_NAME = "Quota Utilization (>80%)"
    print(f"🚦 [{job_id}] Performing Service Limit (Quota) checks...")
    
    def check_project_quotas(project):
        project_id = project['projectId']
        exceeded_quotas = [] # Store findings for this project here
        try:
            credentials, _ = google_auth_default(scopes=SCOPES)
            compute_service = google_api_build('compute', 'v1', credentials=credentials)
            regions = [r['name'] for r in compute_service.regions().list(project=project_id).execute().get('items', [])]
            
            for region in regions:
                quotas = compute_service.regions().get(project=project_id, region=region).execute().get('quotas', [])
                for quota in quotas:
                    usage = quota.get('usage', 0.0)
                    limit = quota.get('limit', 0.0)
                    if limit > 0 and (usage / limit) > 0.8: # Check if usage > 80%
                        # Add the structured data to our list
                        exceeded_quotas.append({
                            "Project": project_id,
                            "Region": region,
                            "Metric": quota['metric'],
                            "Usage": f"{usage/limit:.1%}",
                            "Details": f"{int(usage)}/{int(limit)}"
                        })
        except Exception:
            pass 
        return exceeded_quotas # Return the list of findings (will be empty if none)

    all_findings = []
    for project in all_projects:
        # check_project_quotas returns a list of findings for the project
        findings = check_project_quotas(project)
        if findings:
            # We extend the main list with the items from the returned list
            all_findings.extend(findings)

    print("✅ Service Limit checks complete.")
    
    # Wrap the final list in our standard check group format
    if not all_findings:
        result = {"Check": CHECK_NAME, "Finding": [{"Status": "No quotas found over 80% utilization."}], "Status": "Compliant"}
    else:
        result = {"Check": CHECK_NAME, "Finding": all_findings, "Status": "Action Required"}
    _write_finding_to_gcs(job_id, "Quota_Utilization", result)
    
# --- Vertex AI Remediation Generation ---

def generate_remediation_command(finding_text: str, project_id: str) -> str:
    """
    Uses the Gemini model to generate a gcloud CLI command to remediate a given finding.
    Includes exponential backoff for handling API rate limits.

    Args:
        finding_text (str): The detailed text of the compliance finding.
        project_id (str): The project ID to be used in the generated command.

    Returns:
        str: A single-line gcloud command or an error message.
    """
    # Configuration for the retry logic
    max_retries = 3
    initial_delay = 2  # seconds
    backoff_factor = 2

    for attempt in range(max_retries):
        try:
            # Initialize Vertex AI inside the function for thread safety
            vertexai.init(project=os.environ.get('PROJECT_ID'), location="global")
            model = GenerativeModel("gemini-2.5-flash")

            prompt = f"""
            You are a Google Cloud security expert. Your task is to generate a precise and executable gcloud command to fix the following compliance finding.
            - The command must be a single line.
            - Do not add any explanation, introductory text, or markdown formatting.
            - Use the provided project ID '{project_id}' in the command.
            **Compliance Finding:**
            "{finding_text}"
            **gcloud command:**
            """
            
            response = model.generate_content(prompt)
            command = response.text.strip()

            if command.startswith("gcloud"):
                return command  # Success, exit the loop
            else:
                return "AI could not generate a valid command." # Model returned a non-command, exit

        except core_exceptions.ResourceExhausted as e:
            # This specifically catches the 429 rate limit error
            if attempt < max_retries - 1:
                # Calculate wait time with exponential backoff and random jitter
                delay = (initial_delay * (backoff_factor ** attempt)) + random.uniform(0, 1)
                print(f"⚠️ Rate limit hit for a finding. Retrying in {delay:.2f} seconds... (Attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
            else:
                print(f"❌ Gemini API rate limit exceeded after {max_retries} attempts. Error: {e}")
                return "Error: API rate limit exceeded." # Final failure after all retries

        except Exception as e:
            # For any other error (not a 429), fail immediately without retrying
            print(f"⚠️ An unexpected error occurred calling Gemini API: {e}")
            return "Error generating remediation command."
    
    return "Error: All retry attempts failed." # Should not be reached, but as a fallback


def run_all_checks(scope, scope_id, job_id, progress_callback=None):
    """
    Orchestrates the entire scan by running all check functions in parallel.
    Groups the results into high-level categories for reporting.

    Args:
        scope (str): The scope of the scan (organization, folder, project).
        scope_id (str): The ID of the resource to scan.
        progress_callback (function, optional): A function to call with progress updates.

    Returns:
        dict: A dictionary containing all categorized findings.
    """
    print("🚀 Starting organization scan, fetching all projects first...")
    all_projects = list_projects_for_scope(scope, scope_id)
    if not all_projects:
        print("❌ No active projects found or failed to list projects. Aborting scan.")
        return {"error": "Could not retrieve project list."}
    
    # --- RUN LOCATION SCAN ONCE HERE ---
    print("📍 Discovering all active locations (running once)...")
    active_zones, active_regions = get_active_compute_locations(all_projects)
    print(f"✅ Discovery complete. Found {len(active_zones)} zones and {len(active_regions)} regions.")


    # --- This structured list is the key to accurate progress reporting ---
    # Format: (Category, Friendly Name, function_to_run, (tuple_of_arguments,))
    all_checks_to_run = [
        ("Special", "Organization Policies", check_organization_policies, (scope, scope_id, job_id)),
        ("Security & Identity", "Project IAM Hygiene", check_project_iam_policy, (scope_id, all_projects, job_id)),
        ("Security & Identity", "Service Account Key Rotation", check_sa_key_rotation, (scope_id, all_projects, job_id)),
        ("Security & Identity", "Public GCS Buckets", check_public_buckets, (scope_id, all_projects, job_id)),
        ("Security & Identity", "Open Firewall Rules", check_open_firewall_rules, (scope_id, all_projects, job_id)),
        ("Cost Optimization", "Cost-Saving Recommendations", run_cost_recommendations, (scope_id, all_projects, active_zones, active_regions, job_id)),
        ("Reliability & Resilience", "GCS Bucket Versioning", check_storage_versioning, (scope_id, all_projects, job_id)),
        ("Reliability & Resilience", "GKE Hygiene", check_gke_hygiene, (scope_id, all_projects, job_id)),
        ("Operational Excellence & Observability", "OS Config Agent Coverage", check_os_config_coverage, (scope_id, all_projects, job_id)),
        ("Operational Excellence & Observability", "Monitoring Alert Coverage", check_monitoring_coverage, (scope_id, all_projects, job_id)),
        ("Operational Excellence & Observability", "Standalone VMs", check_standalone_vms, (scope_id, all_projects, job_id)),
        ("Operational Excellence & Observability", "Network Insights", run_network_insights, (scope_id, all_projects, active_zones, active_regions, job_id)),
        ("Operational Excellence & Observability", "Miscellaneous Checks", run_miscellaneous_checks_refactored, (scope, scope_id, all_projects, job_id)),
        ("Operational Excellence & Observability", "Service Quota Limits", run_service_limit_checks_refactored, (scope_id, all_projects, job_id)),
    ]

    if scope == 'organization':
        org_only_checks = [
            ("Security & Identity", "Organization IAM Policy", check_org_iam_policy, (scope_id, job_id)),
            ("Security & Identity", "Security Command Center Status", check_scc_status, (scope_id, job_id)),
            ("Operational Excellence & Observability", "Organization Audit Logging", check_audit_logging, (scope_id, job_id)),
            ("Reliability & Resilience", "Essential Contacts", check_essential_contacts, (scope_id, job_id)),
            ("Reliability & Resilience", "Resilience of Critical Assets", check_resilience_assets, (scope_id, job_id)),
            ("Reliability & Resilience", "Personalized Service Health", check_service_health_status, (scope_id, job_id)),
        ]
        all_checks_to_run.extend(org_only_checks)

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        # This map directly links each running task (future) to its specific name and category.
        future_to_info = {
            executor.submit(func, *args): {"category": category, "name": name}
            for category, name, func, args in all_checks_to_run
        }

        total_checks = len(future_to_info)
        completed_checks = 0

        for future in concurrent.futures.as_completed(future_to_info):
            info = future_to_info[future]
            category = info["category"]
            check_name = info["name"] # This will now ALWAYS be the specific name.

            try:
                future.result()  # Call result to raise exceptions, but don't store return value
            except Exception as e:
                print(f"❌ Check '{check_name}' failed critically: {e}")
                # Optionally write an error finding to a temp file
                error_result = {"Check": check_name, "Finding": [{"Error": str(e)}], "Status": "Error"}
                _write_finding_to_gcs(job_id, f"ERROR_{check_name}".replace(" ", "_"), error_result)
            finally:
                completed_checks += 1
                progress = 5 + int((completed_checks / total_checks) * 90)
                if progress_callback:
                    progress_callback(progress=progress, current_task=f"({completed_checks}/{total_checks}) Finished: {check_name}")
                
    return True

def get_js_script_content(scope, scope_id, job_id):
    """
    Returns the JavaScript content for the interactive HTML report.
    This includes logic for navigation, fetching AI summaries, and displaying data.
    """
    license_header = """
/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"""
    return f"""
        {license_header}
        function showSection(sectionId, clickedLinkElement = null) {{
            document.querySelectorAll('.content-section').forEach(section => {{
                section.style.display = 'none';
            }});
            const targetSection = document.getElementById(sectionId + '-section');
            if (targetSection) {{
                targetSection.style.display = 'block';
            }}
            document.querySelectorAll('.nav-link').forEach(link => {{
                link.classList.remove('active');
            }});
            const targetNavLink = document.querySelector(`.sidebar .nav-link[href='#${{sectionId}}']`);
            if (targetNavLink) {{
                 targetNavLink.classList.add('active');
            }}
            if (history.pushState) {{
                history.pushState(null, null, '#' + sectionId);
            }} else {{
                window.location.hash = sectionId;
            }}
        }}

        document.addEventListener("DOMContentLoaded", function() {{
            const hash = window.location.hash.substring(1);
            if (hash && document.getElementById(hash + '-section')) {{
                showSection(hash);
            }} else {{
                showSection('overview');
            }}
        }});
        
        function toggleSubSection(btn) {{
            const container = btn.nextElementSibling;
            if (container) {{
                if (container.style.display === "none") {{
                    container.style.display = "block";
                    btn.textContent = "Hide Details";
                }} else {{
                    container.style.display = "none";
                    btn.textContent = "View Details";
                }}
            }}
        }}

        // --- UPDATED: generateAiSummary now includes the new Gemini sparkle theme ---
        async function generateAiSummary() {{
            const btn = document.getElementById("summaryBtn");
            const container = document.getElementById("ai-summary-container");
            const content = document.getElementById("ai-summary-content");
            
            btn.disabled = true;
            btn.textContent = "Generating...";

            // Apply the new vibrant blue theme and show the container
            container.classList.add('gemini-summary-card');
            container.style.display = "block";
            
            // Inject the HTML for the new sparkle loader
            const geminiLoaderHtml = `
                <div class="gemini-loader-container">
                    <div class="gemini-loader">
                        <span class="sparkle"></span><span class="sparkle"></span>
                        <span class="sparkle"></span><span class="sparkle"></span>
                    </div>
                    <p>Generating summary with Gemini...</p>
                </div>`;
            content.innerHTML = geminiLoaderHtml;

            try {{
                const response = await fetch('/api/get-summary', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ scope_id: '{scope_id}', job_id: '{job_id}' }}) 
                }});
                if (!response.ok) {{
                    const err = await response.json();
                    throw new Error(err.error || 'Network response was not ok');
                }}
                const data = await response.json();
                content.innerHTML = renderMarkdown(data.summary);
                btn.textContent = "Summary Generated";
            }} catch (error) {{
                container.classList.remove('gemini-summary-card');
                content.innerHTML = `<p style='color:var(--error-color);'><strong>Failed to generate summary:</strong> ${{error.message}}</p>`;
                btn.textContent = "Error - Retry?";
                btn.disabled = false;
            }}
        }}

        // --- The rest of the functions are unchanged ---
        let allInsightsData = [];
        let currentPage = 1;
        const rowsPerPage = 10;

        function renderTablePage(page) {{
            currentPage = page;
            const placeholder = document.getElementById('insights-placeholder');
            if (!placeholder || allInsightsData.length === 0) return;
            const startIndex = (page - 1) * rowsPerPage;
            const endIndex = startIndex + rowsPerPage;
            const pageData = allInsightsData.slice(startIndex, endIndex);
            let tableRowsHtml = '';
            pageData.forEach(insight => {{
                tableRowsHtml += `<tr><td>${{insight.check}}</td><td>${{insight.project}}</td><td>${{insight.resource}}</td><td>${{insight.details}}</td></tr>`;
            }});
            const tableHtml = `<h3>Detailed Insights</h3><table class="styled-table"><thead><tr><th>Check</th><th>Project</th><th>Resource</th><th>Details</th></tr></thead><tbody>${{tableRowsHtml}}</tbody></table>`;
            const totalPages = Math.ceil(allInsightsData.length / rowsPerPage);
            let paginationHtml = '';
            if (totalPages > 1) {{
                paginationHtml = '<div class="pagination-controls">';
                paginationHtml += `<button onclick="renderTablePage(${{page - 1}})" ${{page === 1 ? 'disabled' : ''}}>&laquo; Previous</button>`;
                paginationHtml += `<span> Page ${{page}} of ${{totalPages}} </span>`;
                paginationHtml += `<button onclick="renderTablePage(${{page + 1}})" ${{page === totalPages ? 'disabled' : ''}}>Next &raquo;</button>`;
                paginationHtml += '</div>';
            }}
            placeholder.innerHTML = tableHtml + paginationHtml;
        }}

        async function fetchInsights(btn) {{
            const placeholder = document.getElementById('insights-placeholder');
            const introText = document.querySelector('.insights-intro');
            const loader = btn.querySelector('.loader');
            btn.disabled = true;
            loader.style.display = 'inline-block';
            placeholder.innerHTML = "";
            try {{
                const response = await fetch('/api/get-insights', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ scope: '{scope}', scope_id: '{scope_id}' }})
                }});
                if (!response.ok) {{ throw new Error('Network response was not ok'); }}
                allInsightsData = await response.json();
                if (allInsightsData.length === 0) {{
                    placeholder.innerHTML = "<p>No detailed insights found.</p>";
                }} else {{
                    if (introText) {{ introText.style.display = 'none'; }}
                    renderTablePage(1);
                }}
                btn.style.display = 'none';
            }} catch (error) {{
                placeholder.innerHTML = "<p style='color:var(--error-color);'>Failed to load insights. Check logs.</p>";
                btn.textContent = "Error - Retry?";
                btn.disabled = false;
                loader.style.display = 'none';
            }}
        }}

        function renderMarkdown(text) {{
            text = text.replace(/\\*\\*([^\\*]+)\\*\\*/g, '<strong>$1</strong>');
            text = text.replace(/^\\*\\s(.*)$/gm, '<li>$1</li>');
            text = text.replace(/(<li>.*<\\/li>)/s, '<ul>$1</ul>');
            text = text.replace(/\\n/g, '<br>');
            return text;
        }}

        async function getGeminiSuggestions() {{
            const btn = event.target;
            btn.disabled = true;
            const findingsToFix = [];
            const placeholders = document.querySelectorAll(".remediation-placeholder");

            placeholders.forEach((placeholder) => {{
                const listItem = placeholder.closest('li');
                const detailsDiv = listItem.querySelector('.details');
                const table = detailsDiv.querySelector('table.details-table');
                const index = placeholder.id.split('-')[1];

                let findingText = '';
                let projectId = '';

                if (table) {{
                    // Case 1: Handle structured table data
                    const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent.trim());
                    const projectIndex = headers.indexOf('Project');
                    // Look for multiple possible column names for the recommendation
                    const recommendationIndex = ['Recommendation', 'Issue', 'Role', 'Tier'].find(h => headers.includes(h)) ? headers.findIndex(h => ['Recommendation', 'Issue', 'Role', 'Tier'].includes(h)) : -1;
                    
                    if (recommendationIndex !== -1) {{
                        const rows = table.querySelectorAll('tbody tr');
                        const recommendations = [];
                        rows.forEach((row, i) => {{
                            const cells = row.querySelectorAll('td');
                            const currentProject = (projectIndex !== -1) ? cells[projectIndex].textContent.trim() : '';
                            const recommendation = cells[recommendationIndex].textContent.trim();
                            
                            if (i === 0) {{ projectId = currentProject; }} // Use first project for the batch context

                            // Combine all relevant cell data into a clear, readable string for the LLM
                            let fullRecommendationText = headers.map((h, idx) => `${{h}}: ${{cells[idx].textContent.trim()}}`).join(', ');
                            recommendations.push(fullRecommendationText);
                        }});
                        findingText = recommendations.join('\\n'); // Use newline to separate multiple findings
                    }} else {{
                        findingText = detailsDiv.innerText.trim(); // Fallback if no recommendation column
                    }}
                }} else {{
                    // Case 2: Handle simple text data (no table)
                    findingText = detailsDiv.innerText.trim();
                }}

                // Extract project ID with regex as a final fallback if not found in table
                if (!projectId) {{
                    const projectIdMatch = findingText.match(/Project `([^`]+)`/);
                    if (projectIdMatch) {{ projectId = projectIdMatch[1]; }}
                }}

                if (findingText) {{
                    findingsToFix.push({{ index: index, finding_text: findingText, project_id: projectId }});
                }}
            }});

            if (findingsToFix.length === 0) {{
                btn.textContent = "No Actionable Findings";
                return;
            }}

            const BATCH_SIZE = 5;
            for (let i = 0; i < findingsToFix.length; i += BATCH_SIZE) {{
                const batch = findingsToFix.slice(i, i + BATCH_SIZE);
                btn.textContent = `Getting Fixes (${{i + batch.length}}/${{findingsToFix.length}})...`;
                try {{
                    const response = await fetch('/api/get-suggestions', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ findings: batch }})
                    }});
                    if (!response.ok) {{ throw new Error(`API returned status ${{response.status}}`); }}
                    const suggestions = await response.json();
                    for (const [key, suggestion] of Object.entries(suggestions)) {{
                         const originalIndex = key.split('-')[1];
                         if (suggestion) {{
                            const placeholder = document.getElementById(`fix-${{originalIndex}}`);
                            if (placeholder) {{
                                const preNode = document.createElement("pre");
                                preNode.style.cssText = 'background-color: #f1f3f4; padding: 10px; border-radius: 4px; margin-top: 10px; white-space: pre-wrap; word-break: break-all;';
                                preNode.textContent = suggestion;
                                placeholder.innerHTML = `<strong>Suggested Fix:</strong>`;
                                placeholder.appendChild(preNode);
                            }}
                        }}
                    }}
                }} catch (e) {{
                    console.error("Failed to get Gemini suggestions:", e);
                    btn.textContent = "Error - Check Logs";
                    return;
                }}
            }}
            btn.textContent = "Suggestions Loaded";
        }}
    """

# --- Report Generation ---

def update_status_in_gcs(job_id, scope_id, progress, current_task, status="running"):
    """Creates or overwrites a status file in GCS for the given job."""
    try:
        bucket = storage_client.bucket(RESULTS_BUCKET)
        status_blob = bucket.blob(f"{job_id}/{scope_id}_status.json")
        status_data = {
            "job_id": job_id,
            "scope_id": scope_id,
            "progress": progress,
            "current_task": current_task,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        status_blob.upload_from_string(json.dumps(status_data), content_type='application/json')
        print(f"[{job_id}] Status updated: {progress}% - {current_task}")
    except Exception as e:
        print(f"[{job_id}] WARNING: Could not update status file in GCS: {e}")



def generate_and_upload_reports(scope_id, job_id, all_results):
    """Generates HTML and CSV reports and uploads them to GCS."""
    print(f"[{job_id}] Generating and uploading reports...")
    bucket = storage_client.bucket(RESULTS_BUCKET)
    
    # --- Generate HTML ---
    html_report = generate_html_report(scope_id, job_id, **all_results)
    html_blob = bucket.blob(f"{job_id}/{scope_id}_report.html")
    html_blob.upload_from_string(html_report, content_type='text/html')
    print(f"[{job_id}] HTML report uploaded to {html_blob.public_url}")

    # --- Generate CSV ---
    csv_data = generate_csv_data(all_results)
    csv_blob = bucket.blob(f"{job_id}/{scope_id}_report.csv")
    csv_blob.upload_from_string(csv_data, content_type='text/csv')
    print(f"[{job_id}] CSV report uploaded to {csv_blob.public_url}")

def generate_csv_data(all_results):
    """
    Generates a comprehensive CSV report from the categorized results.

    Args:
        all_results (dict): The dictionary of categorized findings from `run_all_checks`.

    Returns:
        str: A string containing the full report in CSV format.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # --- Write Org Policies Section  ---
    writer.writerow(['Organization Policies'])
    writer.writerow(['Category', 'Policy', 'Expected Value', 'Current Value', 'Status'])
    org_policy_data = all_results.get('Organization Policies')
    if org_policy_data:
        best_practices, current_policies = org_policy_data
        for category, policies in sorted(best_practices.items()):
            if not policies: continue
            for policy in policies:
                policy_id, details = policy['policyId'], policy
                status, current_value_str = "Not Configured", "N/A"
                if policy_id in current_policies:
                    policy_details = current_policies[policy_id]
                    if 'booleanPolicy' in policy_details:
                        current_value = policy_details['booleanPolicy'].get('enforced', False)
                        current_value_str = str(current_value)
                        status = "Compliant" if current_value_str.lower() == details['expectedValue'].lower() else "Non-compliant"
                    else:
                        status, current_value_str = "Unsupported", "List Policy/Other"
                writer.writerow([category, details['displayName'], details['expectedValue'], current_value_str, status])

    # --- Helper to Write Other Sections ---
    def write_section(title, results):
        if not isinstance(results, list) or not results:
            return
        writer.writerow([]) # Spacer row
        writer.writerow([title])
        
        for finding_group in results:
            check_name = finding_group.get('Check', 'Unnamed Check')
            status = finding_group.get('Status', 'N/A')
            details = finding_group.get('Finding')

            if isinstance(details, list) and details and isinstance(details[0], dict):
                # For structured data, create headers and write each dict as a new row
                headers = ['Check', 'Status'] + list(details[0].keys())
                writer.writerow(headers)
                for detail_dict in details:
                    row_data = [check_name, status] + list(detail_dict.values())
                    writer.writerow(row_data)
                writer.writerow([]) # Add a space after a detailed check
            else:
                # Fallback for simple findings (e.g., compliant checks)
                writer.writerow(['Check', 'Status', 'Details'])
                details_str = '; '.join(map(str, details)) if isinstance(details, list) else str(details)
                writer.writerow([check_name, status, details_str])

    # --- Main Loop to Write All Other Sections ---
    for category_name, findings in all_results.items():
        if category_name != 'Organization Policies':
            write_section(category_name, findings)
            
    return output.getvalue()


def generate_html_report(scope, scope_id, job_id, **all_results):
    """
    Generates a dynamic and interactive HTML report from the scan results.

    Args:
        org_id (str): The organization ID.
        job_id (str): The unique ID for this scan job.
        **all_results: The dictionary of categorized findings.

    Returns:
        str: A string containing the full HTML report.
    """
    print(f"[{job_id}] 📊 Generating final report for {scope}: {scope_id}...")
    css_license_header = """
/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"""

    
    def group_findings(findings_list):
        grouped = {}
        status_priority = {"Action Required": 0, "Investigation Recommended": 1, "Informational": 2, "Compliant": 3, "Error": 4}
        for finding in findings_list:
            check_name = finding.get('Check')
            if not check_name: continue
            if check_name not in grouped:
                grouped[check_name] = {"details": [], "Status": finding.get('Status')}
            
            finding_detail = finding.get('Finding')
            
            # FIX: When the finding is already a list (like from cost checks), extend the details. Don't append the list itself.
            if isinstance(finding_detail, list):
                grouped[check_name]["details"].extend(finding_detail)
            elif finding_detail:
                grouped[check_name]["details"].append(finding_detail)
            
            if status_priority.get(finding.get('Status'), 99) < status_priority.get(grouped[check_name]['Status'], 99):
                grouped[check_name]['Status'] = finding.get('Status')
        return grouped

    def create_details_html(details_list):
        """Generates an HTML table if details are a list of dicts, otherwise formats as text."""
        if not details_list: return ""
        if isinstance(details_list[0], dict):
            try:
                headers = details_list[0].keys()
                header_html = "".join(f"<th>{h}</th>" for h in headers)
                rows_html = ""
                for item in details_list:
                    row_data = "".join(f"<td>{item.get(h, '')}</td>" for h in headers)
                    rows_html += f"<tr>{row_data}</tr>"
                return f"<table class='details-table'><thead><tr>{header_html}</tr></thead><tbody>{rows_html}</tbody></table>"
            except Exception:
                return "<br>".join(str(d) for d in details_list)
        return "<br>".join(str(d) for d in details_list)
    
    finding_counter = 0
    
    def build_category_section_html(title, section_id, grouped_data, scope_id, score, org_policy_content=None):
        nonlocal finding_counter
        if not grouped_data and not org_policy_content:
            return ""
        score_class = "high" if score > 90 else "medium" if score > 70 else "low"
        status_map = {
            "Action Required": {"icon": "&#10007;", "class": "action-required"}, "Investigation Recommended": {"icon": "&#9888;", "class": "investigation"},
            "Compliant": {"icon": "&#10003;", "class": "compliant"}, "Error": {"icon": "&#10069;", "class": "error"}, "Informational": {"icon": "&#8505;", "class": "informational"}
        }
        
       
        #  Build the Org Policy HTML as the FIRST LIST ITEM
        org_policy_list_item_html = ""
        if org_policy_content:
            rows, compliant, total = org_policy_content
            # Determine status class for the LI item
            status_class = "compliant" if compliant == total else "action-required"
            icon = "&#10003;" if status_class == "compliant" else "&#10007;"
            
            org_policy_list_item_html = f"""
                <li class="status-{status_class}"> 
                    <span class="icon">{icon}</span> 
                    <div class="check-content">
                        <strong>Organization Policies ({compliant}/{total} Compliant)</strong>
                        <div class="details">
                            <button class="btn toggle-btn" onclick="toggleSubSection(this)" style="margin-top: 5px;">View Details</button>
                            <div class="toggle-container" style="display:none; margin-top: 10px;">
                                <table class="styled-table">
                                    <thead><tr><th>Policy</th><th>Expected Value</th><th>Current Value</th><th>Status</th></tr></thead>
                                    <tbody>{rows}</tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    <span class="status-badge">{compliant}/{total} Compliant</span>
                </li>
            """
        

        items_html = ""
        for check_name, group_data in sorted(grouped_data.items()):
            status = group_data.get("Status", "Informational")
            status_info = status_map.get(status, status_map["Informational"])
            details_html = create_details_html(group_data.get('details', []))
            remediation_placeholder = ""
            if status in ["Action Required", "Investigation Recommended"]:
                remediation_placeholder = f"<div class='remediation-placeholder' id='fix-{finding_counter}'></div>"
                finding_counter += 1
            items_html += f"""
                <li class="status-{status_info['class']}">
                    <span class="icon">{status_info['icon']}</span>
                    <div class="check-content">
                        <strong>{check_name}</strong>
                        <div class="details">{details_html}</div>
                        {remediation_placeholder}
                    </div>
                    <span class="status-badge">{status}</span>
                </li>
            """

        
        footer_html = ""
        if title == "Cost Optimization":
            footer_html = """
                <div class="section-footer">
                    <p class="insights-intro">For a detailed breakdown of potential savings, use the button below to query the Recommender API (this may be slow).</p>
                    <button id="insights-btn" class="btn" onclick="fetchInsights(this)"><span class="loader"></span>Get Detailed Insights</button>
                    <div id="insights-placeholder" style="margin-top: 20px;"></div>
                </div>
            """
        elif title == "Security & Identity" and scope == 'organization':
            footer_html = f"""
                <div class="section-footer">
                    <p>To get more security insights, <a href="https://console.cloud.google.com/active-assist/list/security/recommendations?organizationId={scope_id}&supportedpurview=project" target="_blank">click here to go to your console</a>.</p>
                </div>
            """
        
        # Final assembly: Put BOTH HTML strings INSIDE the <ul>
        return f"""
            <div id="{section_id}-section" class="content-section" style="display: none;">
                <div class="checks-section">
                    <div class="section-header">
                        <h2>{title}</h2>
                        <span class="score-badge score-{score_class}">{score:.0f}% Compliant</span>
                    </div>
                    <ul class="checks-list">
                        {org_policy_list_item_html}
                        {items_html}
                    </ul>
                    {footer_html}
                </div>
            </div>
        """

    # --- CALCULATE SCORES AND DATA FOR ALL SECTIONS ---
    org_policy_content_data = None
    if all_results.get('Organization Policies'):
        best_practices_by_category, current_policies = all_results['Organization Policies']
        org_policy_rows = ""
        compliant_policy_count, total_policies = 0, 0
        for category, policies in sorted(best_practices_by_category.items()):
            if not policies: continue
            org_policy_rows += f'<tr class="category-header"><td colspan="4">{category}</td></tr>'
            for policy in policies:
                total_policies += 1
                policy_id, details = policy['policyId'], policy
                status, current_value_str = "Not Configured", "N/A"
                if policy_id in current_policies:
                    policy_details = current_policies[policy_id]
                    if 'booleanPolicy' in policy_details:
                        current_value = policy_details['booleanPolicy'].get('enforced', False)
                        current_value_str = str(current_value)
                        status = "Compliant" if current_value_str.lower() == details['expectedValue'].lower() else "Non-compliant"
                    else: status, current_value_str = "Unsupported", "List Policy/Other"
                if status == "Compliant": compliant_policy_count += 1
                org_policy_rows += f"<tr><td>{details['displayName']}</td><td>{details['expectedValue']}</td><td>{current_value_str}</td><td class='status-text-{status.lower().replace(' ','-')}'>{status}</td></tr>"
        org_policy_content_data = (org_policy_rows, compliant_policy_count, total_policies)

    category_scores = {}
    category_order = ["Security & Identity", "Cost Optimization", "Reliability & Resilience", "Operational Excellence & Observability"]
    all_other_findings = []
    for category_name in category_order:
        findings = all_results.get(category_name, [])
        all_other_findings.extend(findings)
        grouped_data = group_findings(findings)
        pass_count = sum(1 for g in grouped_data.values() if g.get('Status') == 'Compliant')
        fail_count = sum(1 for g in grouped_data.values() if g.get('Status') in ["Action Required", "Investigation Recommended", "Error"])
        if category_name == "Security & Identity" and org_policy_content_data:
            _, org_compliant, org_total = org_policy_content_data
            pass_count += org_compliant
            fail_count += (org_total - org_compliant)
        total_for_score = pass_count + fail_count
        score = (pass_count / total_for_score) * 100 if total_for_score > 0 else 100
        category_scores[category_name] = score

    grouped_all_findings = group_findings(all_other_findings)
    action_count = sum(1 for g in grouped_all_findings.values() if g.get('Status') == 'Action Required')
    investigation_count = sum(1 for g in grouped_all_findings.values() if g.get('Status') == 'Investigation Recommended')
    compliant_count = sum(1 for g in grouped_all_findings.values() if g.get('Status') == 'Compliant')
    error_count = sum(1 for g in grouped_all_findings.values() if g.get('Status') == 'Error')
    if org_policy_content_data:
        _, org_compliant, org_total = org_policy_content_data
        compliant_count += org_compliant
        action_count += (org_total - org_compliant)

    # --- BUILD HTML FOR EACH HIDDEN CATEGORY SECTION ---
    all_category_sections_html = ""
    for category_name in category_order:
        section_id = category_name.lower().replace(' & ', '-').replace(' ', '-')
        findings = all_results.get(category_name, [])
        grouped_data = group_findings(findings)
        score = category_scores[category_name]
        org_content_for_section = org_policy_content_data if category_name == "Security & Identity" else None
        all_category_sections_html += build_category_section_html(category_name, section_id, grouped_data, scope_id, score, org_policy_content=org_content_for_section)

    # --- BUILD HTML FOR THE NEW SCORE SUMMARY TABLE ---
    score_summary_html = ""
    for category_name, score in category_scores.items():
        section_id = category_name.lower().replace(' & ', '-').replace(' ', '-')
        score_class = "high" if score > 90 else "medium" if score > 70 else "low"
        score_summary_html += f"""
            <tr>
                <td><a href="#{section_id}" onclick="showSection('{section_id}')">{category_name}</a></td>
                <td><span class="score-badge score-{score_class}">{score:.0f}%</span></td>
            </tr>
        """

    # --- ASSEMBLE THE FINAL HTML PAGE ---
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CloudGauge Report: {scope.capitalize()} {scope_id}</title>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
        <style>
            {css_license_header}
            :root {{
                --primary-color: #4285F4; --success-color: #1e8e3e; --error-color: #d93025; --warning-color: #f9ab00; --info-color: #5f6368;
                --background-color: #f8f9fa; --text-color: #3c4043; --light-text-color: #5f6368; --border-color: #dfe1e5; --card-bg-color: #ffffff;
                --font-family: 'Roboto', -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            }}
            body {{ font-family: var(--font-family); margin: 0; background-color: var(--background-color); color: var(--text-color); display: flex; }}
            .sidebar {{ width: 240px; background-color: var(--card-bg-color); border-right: 1px solid var(--border-color); height: 100vh; position: fixed; top: 0; left: 0; padding: 20px; box-sizing: border-box; }}
            .sidebar-header {{ padding-bottom: 20px; margin-bottom: 20px; border-bottom: 1px solid var(--border-color); }}
            .sidebar-header h2 {{ margin: 0; font-size: 20px; }}
            .sidebar .nav-link {{ display: block; padding: 10px 15px; text-decoration: none; color: var(--text-color); border-radius: 5px; margin-bottom: 5px; font-size: 14px; }}
            .sidebar .nav-link:hover {{ background-color: #f1f3f4; }}
            .sidebar .nav-link.active {{ background-color: var(--primary-color); color: white; font-weight: 500; }}
            .main-content {{ margin-left: 240px; padding: 20px; width: calc(100% - 240px); }}
            h1, h2, h3 {{ color: #202124; font-weight: 500; }}
            h2 {{ margin-top: 0; }}
            h3 {{ margin-top: 20px; margin-bottom: 10px; color: #3c4043; }}
            .btn {{ background-color: var(--primary-color); color: white; padding: 10px 15px; border-radius: 5px; border: none; cursor: pointer; font-size: 16px; font-weight: 500; transition: background-color 0.2s ease, box-shadow 0.2s ease; margin-left: 10px; }}
            .btn:hover {{ box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
            .btn.summary-btn {{ background-color: var(--success-color); }}
            .btn.toggle-btn {{ background-color: var(--light-text-color); font-size: 14px; padding: 8px 12px; margin-left: 0; margin-top: 10px; }}
            .overview-container {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; text-align: center; margin-bottom: 30px; }}
            .summary-card {{ background-color: var(--card-bg-color); padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.04); border: 1px solid var(--border-color); }}
            .summary-card h3 {{ margin-top: 0; border-bottom: none; font-size: 18px; color: var(--light-text-color); }}
            .summary-card .count {{ font-size: 48px; font-weight: 700; margin: 10px 0; }}
            .summary-card.compliant .count {{ color: var(--success-color); }}
            .summary-card.action-required .count {{ color: var(--error-color); }}
            .summary-card.investigation .count {{ color: var(--warning-color); }}
            .summary-card.error .count {{ color: var(--info-color); }}
            .checks-section {{ background-color: var(--card-bg-color); padding: 20px 30px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.04); border: 1px solid var(--border-color); margin-bottom: 30px; transition: background-color 0.5s ease; }}
            .section-header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-bottom: 10px; }}
            .section-header h2 {{ border-bottom: none; margin: 0; padding: 0; font-size: 22px; }}
            .score-badge {{ font-size: 14px; font-weight: 500; padding: 5px 12px; border-radius: 16px; color: white; }}
            .score-badge.score-high {{ background-color: var(--success-color); }}
            .score-badge.score-medium {{ background-color: var(--warning-color); }}
            .score-badge.score-low {{ background-color: var(--error-color); }}
            .checks-list {{ list-style: none; padding: 0; margin: 0; }}
            .checks-list li {{ display: flex; align-items: flex-start; padding: 15px 0; border-top: 1px solid var(--border-color); }}
            .checks-list li:first-child {{ border-top: none; padding-top: 0; }}
            .checks-list .icon {{ margin-right: 15px; font-size: 20px; margin-top: 2px; }}
            .checks-list .status-compliant .icon {{ color: var(--success-color); }}
            .checks-list .status-action-required .icon {{ color: var(--error-color); }}
            .checks-list .status-investigation .icon {{ color: var(--warning-color); }}
            .checks-list .status-error .icon, .checks-list .status-informational .icon {{ color: var(--info-color); }}
            .check-content {{ flex-grow: 1; }} .check-content strong {{ font-weight: 500; }}
            .check-content .details {{ color: var(--light-text-color); margin: 5px 0 0 0; }}
            .status-badge {{ font-size: 12px; font-weight: 500; padding: 4px 8px; border-radius: 12px; color: white; white-space: nowrap; }}
            .status-compliant .status-badge {{ background-color: var(--success-color); }}
            .status-action-required .status-badge {{ background-color: var(--error-color); }}
            .status-investigation .status-badge {{ background-color: var(--warning-color); }}
            .styled-table, .details-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            .styled-table th, .styled-table td, .details-table th, .details-table td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border-color); }}
            .details-table {{ border: 1px solid var(--border-color); border-radius: 4px; font-size: 14px; }}
            .details-table th {{ background-color: #f8f9fa; }}
            .details-table td {{ font-size: 13px; word-break: break-all; }}
            .styled-table a {{ color: var(--primary-color); text-decoration: none; font-weight: 500; }}
            .styled-table a:hover {{ text-decoration: underline; }}
            .styled-table th {{ background-color: #f8f9fa; font-weight: 500; }}
            .styled-table .category-header td {{ background-color: #f1f3f4; font-weight: 500; }}
            .status-text-compliant {{ color: var(--success-color); font-weight: 500; }}
            .status-text-non-compliant, .status-text-not-configured {{ color: var(--error-color); font-weight: 500; }}
            .loader {{ border: 4px solid #f3f3f3; border-top: 4px solid var(--primary-color); border-radius: 50%; width: 30px; height: 30px; margin: 20px auto; animation: spin 1s linear infinite; }}
            .section-footer {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-color); }}
            .org-policy-subsection {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-color); }}
            #insights-btn .loader {{ width: 18px; height: 18px; margin-right: 10px; display: none; border-width: 3px; }}
            .pagination-controls {{ margin-top: 20px; text-align: center; }}
            .pagination-controls button {{ background-color: #e8eaed; color: var(--text-color); border: 1px solid var(--border-color); border-radius: 4px; padding: 8px 12px; margin: 0 4px; cursor: pointer; font-size: 14px; }}
            .pagination-controls button:disabled {{ cursor: not-allowed; opacity: 0.6; }}
            .pagination-controls button.active {{ background-color: var(--primary-color); color: white; border-color: var(--primary-color); font-weight: 500; }}
            @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
            .gemini-summary-card {{ background: linear-gradient(135deg, #e8f0fe, #d6e4ff); color: var(--text-color); border-color: #cde0ff; }}
            .gemini-summary-card h2 {{ color: #1967d2; }}
            #ai-summary-content ul {{ padding-left: 20px; }}
            #ai-summary-content li {{ margin-bottom: 10px; }}
            .gemini-loader-container {{ display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px 20px; color: #1967d2; font-weight: 500; }}
            .gemini-loader {{ position: relative; width: 60px; height: 60px; }}
            .gemini-loader .sparkle {{ position: absolute; background-image: url('data:image/svg+xml;utf8,<svg width="20" height="20" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><path d="M50 0L61.2 38.8L100 50L61.2 61.2L50 100L38.8 61.2L0 50L38.8 38.8L50 0Z" fill="%234285F4"/></svg>'); background-size: contain; width: 15px; height: 15px; animation: sparkle 1.5s ease-in-out infinite; }}
            .gemini-loader .sparkle:nth-child(1) {{ top: 0; left: 50%; transform: translateX(-50%); animation-delay: 0s; }}
            .gemini-loader .sparkle:nth-child(2) {{ top: 50%; right: 0; transform: translateY(-50%); animation-delay: 0.3s; }}
            .gemini-loader .sparkle:nth-child(3) {{ bottom: 0; left: 50%; transform: translateX(-50%); animation-delay: 0.6s; }}
            .gemini-loader .sparkle:nth-child(4) {{ top: 50%; left: 0; transform: translateY(-50%); animation-delay: 0.9s; }}
            @keyframes sparkle {{ 0%, 100% {{ opacity: 0; transform: scale(0.5) translateY(-50%) rotate(0deg); }} 50% {{ opacity: 1; transform: scale(1) translateY(-50%) rotate(180deg); }} }}
        </style>
    </head>
    <body>
        <nav class="sidebar">
            <div class="sidebar-header"><h2>Report Sections</h2></div>
            <a href="#overview" class="nav-link active" onclick="showSection('overview', this)">Overview</a>
            <a href="#security-identity" class="nav-link" onclick="showSection('security-identity', this)">Security & Identity</a>
            <a href="#cost-optimization" class="nav-link" onclick="showSection('cost-optimization', this)">Cost Optimization</a>
            <a href="#reliability-resilience" class="nav-link" onclick="showSection('reliability-resilience', this)">Reliability & Resilience</a>
            <a href="#operational-excellence-observability" class="nav-link" onclick="showSection('operational-excellence-observability', this)">Operational Excellence</a>
        </nav>
        <div class="main-content">
            <h1>CloudGauge Report</h1>
            <p style="color: var(--light-text-color);">Scope: {scope.capitalize()} | ID: {scope_id} | Report ID: {job_id}</p>
            
            <div id="overview-section" class="content-section">
                <div class="checks-section">
                    <h2>Overview</h2>
                    <div class="overview-container">
                        <div class="summary-card action-required"><h3>Action Required</h3><p class="count">{action_count}</p></div>
                        <div class="summary-card investigation"><h3>Investigation Recommended</h3><p class="count">{investigation_count}</p></div>
                        <div class="summary-card compliant"><h3>Compliant</h3><p class="count">{compliant_count}</p></div>
                        <div class="summary-card error"><h3>Errors</h3><p class="count">{error_count}</p></div>
                    </div>
                    <div class="section-footer" style="display:flex; justify-content:center; margin-left:-10px;">
                        <button class="btn" onclick="getGeminiSuggestions()">Get Remediation Suggestions</button>
                        <button id="summaryBtn" class="btn summary-btn" onclick="generateAiSummary()">Get AI Summary</button>
                    </div>
                </div>
                <div id="ai-summary-container" class="checks-section" style="display: none;">
                    <h2>Executive Summary (AI Generated)</h2>
                    <div id="ai-summary-content" style="line-height: 1.6;"></div>
                </div>
                <div class="checks-section">
                    <h2>Review Scores</h2>
                    <table class="styled-table">
                        <tbody>{score_summary_html}</tbody>
                    </table>
                </div>
            </div>
            {all_category_sections_html}
        </div>
        <script>
            {get_js_script_content(scope, scope_id, job_id)}
        </script>
    </body>
    </html>
    """
    return html_content

# --- Flask API Endpoints ---

@app.route('/', methods=['GET'])
def index():
    """Renders the main landing page with a dynamic form to select a resource."""
    return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>CloudGauge</title>
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
            <style>
                :root { --primary-color: #4285F4; --background-color: #f8f9fa; --text-color: #3c4043; --border-color: #dfe1e5; --card-bg-color: #ffffff; }
                body { font-family: 'Roboto', sans-serif; margin: 0; background-color: var(--background-color); color: var(--text-color); display: flex; align-items: center; justify-content: center; height: 100vh; }
                .scan-card { background-color: var(--card-bg-color); padding: 40px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.08); text-align: center; max-width: 500px; width: 100%; }
                h1 { font-weight: 500; }
                p { color: #5f6368; margin-bottom: 30px; }
                form { display: flex; flex-direction: column; gap: 20px; }
                .form-group { text-align: left; }
                label { font-weight: 500; display: block; margin-bottom: 5px; }
                select, button { font-size: 16px; padding: 12px; border-radius: 5px; border: 1px solid var(--border-color); width: 100%; box-sizing: border-box; }
                button { background-color: var(--primary-color); color: white; cursor: pointer; font-weight: 500; }
                button:disabled { background-color: #e0e0e0; cursor: not-allowed; }
                #loader { display: none; margin-top: 10px; font-style: italic; color: var(--text-color); }
            </style>
        </head>
        <body>
            <div class="scan-card">
                <h1>Review Your Cloud Environment</h1>
                <p>Select a scope and resource to begin a comprehensive review.</p>
                <form action="/scan" method="post">
                    <div class="form-group">
                        <label for="scope">1. Select Scan Scope:</label>
                        <select id="scope" name="scope">
                            <option value="" disabled selected>-- Choose a scope --</option>
                            <option value="organization">Organization</option>
                            <option value="folder">Folder</option>
                            <option value="project">Project</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="scope_id">2. Select Resource:</label>
                        <select id="scope_id" name="scope_id" required disabled>
                            <option value="" disabled selected>-- Select scope first --</option>
                        </select>
                        <div id="loader">Loading resources...</div>
                    </div>
                    <button id="submit-btn" type="submit" disabled>Start Scan</button>
                </form>
            </div>

            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    const scopeSelect = document.getElementById('scope');
                    const resourceSelect = document.getElementById('scope_id');
                    const loader = document.getElementById('loader');
                    const submitBtn = document.getElementById('submit-btn');

                    scopeSelect.addEventListener('change', async function() {
                        const selectedScope = this.value;
                        if (!selectedScope) return;

                        // Reset and show loader
                        resourceSelect.innerHTML = '<option value="" disabled selected>-- Loading... --</option>';
                        resourceSelect.disabled = true;
                        submitBtn.disabled = true;
                        loader.style.display = 'block';

                        try {
                            const response = await fetch(`/api/list-resources?scope=${selectedScope}`);
                            if (!response.ok) {
                                throw new Error('Failed to fetch resources.');
                            }
                            const resources = await response.json();

                            // Clear dropdown and add new options
                            resourceSelect.innerHTML = '<option value="" disabled selected>-- Select a resource --</option>';
                            if (resources.length > 0) {
                                resources.forEach(resource => {
                                    const option = new Option(resource.name, resource.id);
                                    resourceSelect.appendChild(option);
                                });
                                resourceSelect.disabled = false;
                            } else {
                                resourceSelect.innerHTML = '<option value="" disabled selected>-- No resources found --</option>';
                            }
                        } catch (error) {
                            console.error('Error:', error);
                            resourceSelect.innerHTML = '<option value="" disabled selected>-- Error loading resources --</option>';
                        } finally {
                            loader.style.display = 'none';
                        }
                    });

                    resourceSelect.addEventListener('change', function() {
                        if (this.value) {
                            submitBtn.disabled = false;
                        } else {
                            submitBtn.disabled = true;
                        }
                    });
                });
            </script>
        </body>
        </html>
    """)

@app.route('/scan', methods=['POST'])
def create_scan_task():
    """
    Receives the scope ( Org, Folder or Project ) from the form, creates an asynchronous Cloud Task
    to perform the scan, and redirects the user to a status page.
    """
    scope = request.form['scope']
    scope_id = request.form['scope_id']
    if not scope_id or not scope:
        return "Scope and ID are required.", 400

    job_id = str(uuid.uuid4())
    print(f"Creating scan task for {scope}: {scope_id} with Job ID: {job_id}")

    task = {
        "http_request": {
            "http_method": tasks_v2.HttpMethod.POST,
            "url": f"{WORKER_URL}/run-scan",
            "headers": {"Content-Type": "application/json"},
            "oidc_token": {
                "service_account_email": os.environ.get('SERVICE_ACCOUNT_EMAIL')
            },
        }
    }
    # NEW: Use a generic payload
    task["http_request"]["body"] = json.dumps({"scope": scope, "scope_id": scope_id, "job_id": job_id}).encode()

    parent = tasks_client.queue_path(PROJECT_ID, LOCATION, TASK_QUEUE)
    tasks_client.create_task(parent=parent, task=task)
    
    # NEW: Pass both IDs to the status page
    return redirect(url_for('get_status', job_id=job_id, scope_id=scope_id, scope=scope))

@app.route('/run-scan', methods=['POST'])
def run_scan_worker():
    """
    The worker endpoint triggered by Cloud Tasks. It executes the main `run_all_checks`
    function and uploads the generated reports to Google Cloud Storage.
    """
    data, scope_id, job_id = request.get_json(force=True), None, None
    try:
        scope = data['scope']
        scope_id = data['scope_id']
        job_id = data['job_id']
        print(f"[{job_id}] Worker received task for ID: {scope_id}")

        update_status_in_gcs(job_id, scope_id, 5, "Initializing scan and listing resources...")

        # --- Throttling logic setup ---
        # We will only update GCS if at least 2 seconds have passed since the last update.
        UPDATE_INTERVAL = 2  # seconds
        last_update_time = 0
        # A lock ensures thread-safe updates to the last_update_time variable.
        lock = threading.Lock()
        final_progress = {"progress": 0, "task": ""}

        def progress_reporter(progress, current_task):
            nonlocal last_update_time
            current_time = time.time()

            # Store the latest progress regardless of timing
            final_progress["progress"] = progress
            final_progress["task"] = current_task

            with lock:
                if (current_time - last_update_time) > UPDATE_INTERVAL:
                    update_status_in_gcs(job_id, scope_id, progress, current_task)
                    last_update_time = current_time

        run_all_checks(scope, scope_id, job_id, progress_callback=progress_reporter)

        # --- Final, unconditional update after checks complete ---
        # This ensures the user sees the 100% completion of the checks phase, even if
        # it happened within the 2-second throttle window.
        if final_progress["task"]:
            update_status_in_gcs(job_id, scope_id, final_progress["progress"], final_progress["task"])

        update_status_in_gcs(job_id, scope_id, 98, "Generating final HTML and CSV reports...")

        # 2. Read all results back from /gcs for report generation
        all_results = _read_all_findings_from_gcs(job_id)
        # Also read the special-cased org policy data
        org_policy_data = _read_org_policies_from_gcs(job_id)
        if org_policy_data[0] and org_policy_data[1]:
            all_results["Organization Policies"] = org_policy_data

        html_report = generate_html_report(scope, scope_id, job_id, **all_results)
        csv_report = generate_csv_data(all_results)


        bucket = storage_client.bucket(RESULTS_BUCKET)
        bucket.blob(f"{job_id}/{scope_id}_report.html").upload_from_string(html_report, content_type='text/html')
        bucket.blob(f"{job_id}/{scope_id}_report.csv").upload_from_string(csv_report, content_type='text/csv')

        update_status_in_gcs(job_id, scope_id, 100, "Scan complete!", status="completed")

        print(f"[{job_id}] Task completed successfully.")
        return "Scan completed and reports uploaded.", 200
    except Exception as e:
        print(f"[{job_id}] CRITICAL ERROR in worker for ID {scope_id}: {e}")
        traceback.print_exc()
        if job_id and scope_id:
             update_status_in_gcs(job_id, scope_id, 100, f"A critical error occurred: {e}", status="error")
        return "Internal Server Error", 500
    finally:
        # CRUCIAL: Clean up all intermediate files from GCS for this job_id
        if job_id:
            print(f"[{job_id}] Cleaning up intermediate files from GCS...")
            try:
                bucket = storage_client.bucket(RESULTS_BUCKET)
                prefix_to_delete = f"intermediate/{job_id}/"
                blobs_to_delete = list(bucket.list_blobs(prefix=prefix_to_delete))
                if blobs_to_delete:
                    bucket.delete_blobs(blobs_to_delete)
                    print(f"[{job_id}] Deleted {len(blobs_to_delete)} intermediate files.")
            except Exception as e:
                logging.error(f"[{job_id}] Failed to clean up intermediate GCS files: {e}")
    
@app.route('/api/status/<string:job_id>/<string:scope_id>')
def api_check_status(job_id, scope_id):
    """
    API endpoint for the front-end to poll. Checks the status.json file
    in GCS to provide real-time progress updates.
    """
    try:
        bucket = storage_client.bucket(RESULTS_BUCKET)
        status_blob = bucket.blob(f"{job_id}/{scope_id}_status.json")

        if status_blob.exists():
            # If the status file is there, return its content
            status_data = json.loads(status_blob.download_as_text())
            return jsonify(status_data)
        else:
            # If the worker hasn't created the file yet, return a pending state
            return jsonify({"status": "pending", "progress": 0, "current_task": "Waiting for task to start..."})
            
    except Exception as e:
        print(f"Error checking status for job {job_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/report/<string:job_id>/<string:scope_id>')
def view_report(job_id, scope_id):
    """Serves the final HTML report from GCS to the user."""
    try:
        bucket = storage_client.bucket(RESULTS_BUCKET)
        report_blob_name = f"{job_id}/{scope_id}_report.html"
        blob = bucket.blob(report_blob_name)

        if not blob.exists():
            return "Report not found or is still generating.", 404
        
        report_html = blob.download_as_text()
        return report_html

    except Exception as e:
        print(f"Error fetching report {job_id} from GCS: {e}")
        return "Could not retrieve report.", 500
    
@app.route('/api/get-insights', methods=['POST'])
def get_insights():
    """
    On-demand endpoint to run a slower, more detailed scan for cost optimization
    insights, separate from the main recommendations.
    """
    data = request.get_json()
    scope = data.get('scope')
    scope_id = data.get('scope_id')
    if not scope_id or not scope:
        return jsonify({"error": "Scope and Scope ID are required."}), 400

    
    def run_cost_optimization_insights(scope, scope_id):
        print("💡 Performing on-demand detailed INSIGHT scan...")
        all_findings = []
        all_projects = list_projects_for_scope(scope, scope_id)
        if not all_projects:
            return []
        
        active_zones, active_regions = get_active_compute_locations(all_projects)
        from google.cloud.recommender_v1 import RecommenderClient
        recommender_client = RecommenderClient()

        
        global_insights = {
            "Idle Images": "google.compute.image.IdleResourceInsight",
        }
        regional_insights = {
            "Unassociated IP Addresses": "google.compute.address.IdleResourceInsight",
            "Idle Cloud SQL Instances": "google.cloudsql.instance.IdleInsight",
        }
        zonal_insights = {
            "Idle Disks": "google.compute.disk.IdleResourceInsight",
            "VM CPU Usage": "google.compute.instance.CpuUsageInsight",
            "VM CPU Prediction": "google.compute.instance.CpuUsagePredictionInsight",
            "VM Memory Usage": "google.compute.instance.MemoryUsageInsight",
            "VM Memory Prediction": "google.compute.instance.MemoryUsagePredictionInsight",
            "VM Bandwidth": "google.compute.instance.NetworkThroughputInsight",
            "MIG CPU Usage": "google.compute.instanceGroupManager.CpuUsageInsight",
            "MIG Memory Usage": "google.compute.instanceGroupManager.MemoryUsageInsight",
        }
        
        for project in all_projects:
            project_id = project['projectId']
            
            # Scan for GLOBAL insights
            for check_name, insight_type_id in global_insights.items():
                parent = f"projects/{project_id}/locations/global/insightTypes/{insight_type_id}"
                try:
                    insights = recommender_client.list_insights(parent=parent)
                    for insight in insights:
                        resource_name = insight.target_resources[0].split('/')[-1] if insight.target_resources else 'N/A'
                        all_findings.append({"check": check_name, "project": project_id, "resource": resource_name, "details": insight.description})
                except Exception as e: logging.warning(f"Could not check global insight for {project_id}: {e}")

            # Scan for REGIONAL insights
            for loc in active_regions:
                for check_name, insight_type_id in regional_insights.items():
                    parent = f"projects/{project_id}/locations/{loc}/insightTypes/{insight_type_id}"
                    try:
                        insights = recommender_client.list_insights(parent=parent)
                        for insight in insights:
                            resource_name = insight.target_resources[0].split('/')[-1] if insight.target_resources else 'N/A'
                            all_findings.append({"check": check_name, "project": project_id, "resource": resource_name, "details": insight.description})
                    except Exception as e: logging.warning(f"Could not check regional insight for {project_id}: {e}")
            
            # Scan for ZONAL insights
            for loc in active_zones:
                for check_name, insight_type_id in zonal_insights.items():
                    parent = f"projects/{project_id}/locations/{loc}/insightTypes/{insight_type_id}"
                    try:
                        insights = recommender_client.list_insights(parent=parent)
                        for insight in insights:
                            resource_name = insight.target_resources[0].split('/')[-1] if insight.target_resources else 'N/A'
                            all_findings.append({"check": check_name, "project": project_id, "resource": resource_name, "details": insight.description})
                    except Exception as e: logging.warning(f"Could not check zonal isnight for {project_id}: {e}")
        
        return all_findings

    try:
        insights = run_cost_optimization_insights(scope, scope_id)
        return jsonify(insights)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"An internal error occurred while fetching insights: {e}"}), 500
    

@app.route('/api/get-summary', methods=['POST'])
def get_summary():
    """
    On-demand endpoint to generate a Gemini-powered executive summary
    from the full CSV report data stored in GCS.
    """
    try:
        data = request.get_json()
        scope_id = data.get('scope_id')  # CORRECTED
        job_id = data.get('job_id')
        print(f"🤖 Received on-demand request for AI summary for job {job_id}...")

        if not scope_id or not job_id:
            return jsonify({"error": "Scope ID and Job ID are required."}), 400


        # 1. Fetch the context (the full CSV report) from GCS
        bucket = storage_client.bucket(RESULTS_BUCKET)
        csv_blob_name = f"{job_id}/{scope_id}_report.csv"
        blob = bucket.blob(csv_blob_name)
        
        if not blob.exists():
            return jsonify({"error": "CSV report not found. Cannot generate summary."}), 404
            
        csv_data = blob.download_as_text()

        # 2. Initialize Vertex AI and the Generative Model
        vertexai.init(project=os.environ.get('PROJECT_ID'), location="global")
        # Using 2.5 Flash as it's great for summarization and fast
        model = GenerativeModel("gemini-2.5-flash") 

        # 3. Use the optimized prompt
        prompt = f"""
        You are a strategic Google Cloud advisor specializing in security posture enhancement and cost optimization. Your task is to provide a balanced and action-oriented executive summary based on the following compliance and best practices report, which is provided in CSV format.

        **Report Data:**
        ```csv
        {csv_data}
        ```

        **Instructions:**
        1.  Start with a single, concise introductory sentence that summarizes the overall state of the organization's cloud environment.
        2.  Identify the top 3-5 primary opportunities for enhancement and optimization. Use a bulleted list.
        3.  For each area, briefly explain the implication and the opportunity in plain, business-focused language. Frame the points constructively.
            * Instead of: "High security risk due to publicly accessible storage buckets."
            * Use language like: "Opportunity to Enhance Data Security: By adjusting permissions on several storage buckets, we can significantly strengthen our data security posture."
            * Instead of: "Significant cost savings are being missed by not addressing idle VMs."
            * Use language like: "Opportunity for Cost Optimization: A number of virtual machines have been identified as idle, representing a clear opportunity to reduce operational costs."
        4.  Conclude with a brief, forward-looking statement about the recommended next steps to capitalize on these opportunities.
        5.  Keep the entire summary professional, concise, and easy for a non-technical executive to understand. Do not repeat the raw data from the report.
        6.  **Tone and Voice:** Adopt a constructive and partnership-oriented tone. The goal is to highlight opportunities for improvement and strategic gains, not to create alarm. Focus on what can be achieved.
        7.  Format your entire response in GitHub-flavored Markdown.
        """
        
        # 4. Generate the summary
        response = model.generate_content(prompt)
        
        print(f"✅ AI summary generated successfully for job {job_id}.")
        return jsonify({"summary": response.text})

    except Exception as e:
        print(f"CRITICAL ERROR in /api/get-summary: {e}")
        traceback.print_exc()
        return jsonify({"error": "An internal error occurred while generating the AI summary."}), 500

@app.route('/api/get-suggestions', methods=['POST'])
def get_suggestions():
    """
    Receives a batch of findings from the report and uses the Gemini API
    to generate gcloud remediation commands for each one.
    """
    try:
        data = request.get_json()
        actionable_findings = data.get('findings', [])
        
        remediation_map = {}
        if actionable_findings:
            print(f"🤖 On-demand request for {len(actionable_findings)} Gemini suggestions...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                def call_gemini(finding_info):
                    # The generate_remediation_command function already has its own internal try/except,
                    # which is good for handling individual AI call failures.
                    return generate_remediation_command(finding_info['finding_text'], finding_info['project_id'])
                
                results = executor.map(call_gemini, actionable_findings)
            
            for i, command in enumerate(results):
                # The key is now based on the original index from the batch
                original_index = actionable_findings[i]['index']
                remediation_map[f"finding-{original_index}"] = command

            print("✅ Gemini on-demand suggestions received.")

        return jsonify(remediation_map)

    except Exception as e:
        # This is the crucial safety net. It will catch any unhandled exceptions.
        print(f"CRITICAL ERROR in /api/get-suggestions: {e}")
        traceback.print_exc()
        # Return a 500 error to the browser so the 'catch' block is triggered.
        return jsonify({"error": "An internal error occurred on the server."}), 500

@app.route('/status/<string:job_id>/<string:scope>/<string:scope_id>')
def get_status(job_id, scope, scope_id):
    """
    Renders the status page that users see while a scan is running.
    It simulates progress and polls the `/api/status` endpoint. Also generates
    a signed URL for the CSV download.
    """
    if not scope_id:
        return "Error:  ID is missing from the status URL.", 400

    signed_csv_url = "#" 
    try:
        # --- START SIGNED LOGIC ---
        
        # 1. Get the default credentials from the metadata server
        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        
        # 2. Manually refresh them to get a usable access token
        auth_req = google.auth.transport.requests.Request()
        creds.refresh(auth_req)
        access_token = creds.token

        # 3. Get the service account email from the environment variable
        signer_email = os.environ.get('SERVICE_ACCOUNT_EMAIL')

        # 4. Generate the signed URL, providing BOTH the email and the access token
        #    This tells the library: "Use this token to authorize a request for
        #    'signer_email' to sign the following content."
        bucket = storage_client.bucket(RESULTS_BUCKET)
        csv_blob_name = f"{job_id}/{scope_id}_report.csv"
        blob = bucket.blob(csv_blob_name)
        
        expiration_time = datetime.now(timezone.utc) + timedelta(hours=1)
        
        signed_csv_url = blob.generate_signed_url(
            version="v4",
            expiration=expiration_time,
            method="GET",
            service_account_email=signer_email,
            access_token=access_token  # <-- Pass the fetched token here
        )
        # --- END SIGNED LOGIC ---
        
    except Exception as e:
        print(f"Could not generate signed URL for job {job_id}: {e}")
    
    # Pass the signed URL into the template
    return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Scan in Progress...</title>
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
            <style>
                :root { --primary-color: #4285F4; --success-color: #1e8e3e; --background-color: #f8f9fa; --text-color: #3c4043; --border-color: #dfe1e5; --card-bg-color: #ffffff; }
                body { font-family: 'Roboto', sans-serif; margin: 0; background-color: var(--background-color); color: var(--text-color); display: flex; align-items: center; justify-content: center; height: 100vh; }
                .status-card { background-color: var(--card-bg-color); padding: 40px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.08); border: 1px solid var(--border-color); text-align: center; max-width: 600px; width: 100%; }
                h1 { color: #202124; font-weight: 500; margin-top: 0; }
                p { color: #5f6368; margin-bottom: 30px; line-height: 1.6; }
                .progress-bar-container { background-color: #e9ecef; border-radius: 8px; height: 16px; width: 100%; margin: 20px 0; overflow: hidden; }
                .progress-bar { background-color: var(--primary-color); height: 100%; width: 0%; border-radius: 8px; transition: width 0.4s linear; }
                .loader { border: 4px solid #f3f3f3; border-top: 4px solid var(--primary-color); border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
                .status-message { font-weight: 500; height: 24px; }
                .button-group { display: flex; gap: 15px; justify-content: center; margin-top: 20px; }
                .btn { text-decoration: none; display: inline-block; background-color: var(--primary-color); color: white; padding: 12px 20px; border-radius: 5px; border: none; cursor: pointer; font-size: 16px; font-weight: 500; transition: background-color 0.2s ease, box-shadow 0.2s ease; }
                .btn:hover { box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                .btn.secondary { background-color: #e8eaed; color: var(--text-color); }
                .success-icon { font-size: 48px; color: var(--success-color); }
            </style>
        </head>
        <body>
            <div id="status-card" class="status-card">
                </div>
            
            <script>
                const job_id = "{{ job_id }}";
                const scope_id = "{{ scope_id }}";
                const signed_csv_url = "{{ signed_csv_url | safe }}"; 
                const card = document.getElementById('status-card');

                // --- UI Update Functions  ---
                function showInProgressUI() {
                    document.title = "Scan in Progress...";
                    card.innerHTML = `
                        <h1>Scan in Progress</h1>
                        <p>Your request for job <strong>${job_id}</strong> is being processed. This may take several minutes.</p>
                        <div class="loader"></div>
                        <p id="status-message" class="status-message">Initializing...</p>
                        <div class="progress-bar-container">
                            <div id="progress-bar" class="progress-bar"></div>
                        </div>
                        <p id="progress-text">0%</p>
                    `;
                }

                function showReadyUI() {
                    document.title = "Report Ready!";
                    const report_url = `/report/${job_id}/${scope_id}`;
                    card.innerHTML = `
                        <div class="success-icon">&#10003;</div>
                        <h1>Scan Complete!</h1>
                        <p>Your report is ready. You can now view the interactive report online or download the raw data as a CSV file.</p>
                        <div class="button-group">
                            <a href="${report_url}" target="_blank" class="btn">View Interactive Report</a>
                            <a href="${signed_csv_url}" class="btn secondary">Download CSV Report</a>
                        </div>
                    `;
                }

                function showErrorUI(message) {
                    document.title = "Scan Failed!";
                    card.innerHTML = `
                        <div class="success-icon" style="color: var(--error-color);">&#10007;</div>
                        <h1>Scan Failed</h1>
                        <p>An error occurred while processing your request for job <strong>${job_id}</strong>.</p>
                        <p style="font-family: monospace; background-color: #f1f3f4; padding: 10px; border-radius: 4px;">${message || 'Unknown error. Please check the application logs.'}</p>
                    `;
                }
                
                // --- Logic to run on page load ---
                showInProgressUI();
                
                const progressBar = document.getElementById('progress-bar');
                const progressText = document.getElementById('progress-text');
                const statusMessage = document.getElementById('status-message');

                // --- Real-time API Polling ---
                async function checkStatus() {
                    try {
                        const response = await fetch(`/api/status/${job_id}/${scope_id}`);
                        if (!response.ok) {
                            // Handle server errors during polling
                            throw new Error(`API returned status ${response.status}`);
                        }
                        const data = await response.json();

                        // Update the UI with real data from the backend
                        if (progressBar) progressBar.style.width = data.progress + '%';
                        if (progressText) progressText.textContent = Math.round(data.progress) + '%';
                        if (statusMessage) statusMessage.textContent = data.current_task;

                        // Check the final status
                        if (data.status === 'completed') {
                            clearInterval(statusInterval); // Stop polling
                            setTimeout(showReadyUI, 500); // Short delay to show 100%
                        } else if (data.status === 'error') {
                            clearInterval(statusInterval); // Stop polling
                            showErrorUI(data.current_task);
                        }
                    } catch (e) {
                        console.error("Failed to get status:", e);
                        // Optional: You could stop polling after several consecutive errors
                    }
                }
                
                const statusInterval = setInterval(checkStatus, 3000); // Check every 3 seconds
                checkStatus(); // Initial check on page load
            </script>
        </body>
        </html>
    """, job_id=job_id, scope_id=scope_id, scope=scope, signed_csv_url=signed_csv_url)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
