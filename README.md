# **CloudGauge**

**Note:** This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

CloudGauge is a web application designed to run a comprehensive set of compliance, security, cost optimization, and best-practice checks against a Google Cloud Organization.

It is built with Python/Flask and deployed as a serverless application on **Google Cloud Run**. The application leverages **Cloud Tasks** to run scans asynchronously, ensuring that even very large organizations can be scanned without browser timeouts.

Final results are delivered as an interactive **HTML report** and a **CSV file** stored in a Google Cloud Storage bucket. The reports also feature **Gemini-powered** executive summaries and `gCloud` remediation suggestions.

## **Table of Contents**

* [Features](#features)  
* [Architecture](#architecture)  
* [Deployment Instructions](#deployment-instructions)  
  * [Common Prerequisites (Required for all methods)](#common-prerequisites-\(required-for-all-methods\))  
  * [Method 1: Deploy from Source (Recommended)](#method-1:-deploy-from-source-\(recommended\))  
  * [Method 2: Manual Build & Deploy via gcloud](#method-2:-manual-build-&-deploy-via-gcloud)  
* [How to Use](#how-to-use)  
* [Troubleshooting](#troubleshooting)  
* [License & Support](#license-&-support)

## **Features** {#features}

CloudGauge scans your organization across several key domains, modeled after the Google Cloud Architecture Framework.

### **Security & Identity**

* **Organization Policies**: Checks boolean policies against a list of best practices.  
* **Organization IAM**: Scans for public principals (`allUsers`, `allAuthenticatedUsers`) and primitive roles (`owner`, `orgAdmin`) at the org level.  
* **Project IAM**: Scans all projects for the use of primitive `roles/owner` and `roles/editor`.  
* **Security Command Center**: Verifies that SCC Premium is enabled.  
* **SA Key Rotation**: Finds user-managed service account keys older than 90 days.  
* **Public GCS Buckets**: Detects GCS buckets that are publicly accessible.  
* **Open Firewall Rules**: Scans all VPCs for firewall rules open to the internet (`0.0.0.0/0`).

### **Cost Optimization**

* **Idle Resources**: Finds idle Cloud SQL instances, VMs, persistent disks, and unassociated IP addresses.  
* **Rightsizing**: Identifies overprovisioned VMs and underutilized reservations.  
* **Cost Insights**: Provides an on-demand, detailed scan for CPU/memory usage, idle images, and more.

### **Reliability & Resilience**

* **Essential Contacts**: Ensures contacts are configured for `SECURITY`, `TECHNICAL`, and `LEGAL` categories.  
* **Service Health**: Verifies that the Personalized Service Health API is enabled.  
* **Cloud SQL Resilience**: Checks for High Availability (HA) configuration, automated backups, and Point-in-Time Recovery (PITR).  
* **GCS Versioning**: Finds buckets without object versioning enabled.  
* **GKE Hygiene**: Checks for clusters not on a release channel and node pools with auto-upgrade disabled.  
* **Resilience Assets**: Identifies zonal MIGs (recommends regional) and single-region disk snapshots.

### **Operational Excellence & Observability**

* **Audit Logging**: Checks for an organization-level log sink.  
* **OS Config Coverage**: Identifies running VMs (excluding GKE/Dataproc) that are not reporting to the OS Config service.  
* **Monitoring Coverage**: Scans for projects missing key alert policies (e.g., Quota, Cloud SQL, GKE).  
* **Network Analyzer**: Ingests and normalizes insights for VPC, GKE, and PSA IP address utilization.  
* **Standalone VMs**: Finds VMs not managed by a Managed Instance Group (MIG).  
* **Quota Utilization**: Identifies any regional compute quotas exceeding 80% utilization.  
* **Unattended Projects**: Flags projects with low utilization.

##  **Architecture** {#architecture}

The application follows a robust, scalable, and asynchronous "fire-and-forget" pattern. This ensures the user gets an immediate response while the heavy work (which can take many minutes) is done in the background.

1. **UI Trigger**: A user navigates to the Cloud Run URL and submits an Organization ID.  
2. **Task Creation**: The `/scan` endpoint creates a **Cloud Task** with the scan details and redirects the user to a status page.  
3. **Background Worker**: Cloud Tasks securely invokes the `/run-scan` endpoint in the background.  
4. **Parallel Processing**: The worker executes dozens of checks, running project-level scans in parallel using a thread pool.  
5. **Report Storage**: The worker generates the HTML/CSV reports and uploads them to Google Cloud Storage.  
6. **Status Polling**: The user's status page polls an API endpoint until the report files are found in GCS, at which point it displays the download links.

Code snippet

```
graph TD
    subgraph "User Interaction (Fast)"
        A[User's Browser] -- 1. Submits Org ID --> B{Cloud Run Service: /scan};
        B -- 2. Creates Task (milliseconds) --> C[Cloud Tasks Queue];
        B -- 3. Redirects User --> G{Status Page};
    end

    subgraph "Background Processing (Slow)"
      direction LR
      D{Cloud Run Service: /run-scan} -- 5. Runs Checks (Parallel)--> E[Google Cloud APIs];
      D -- 6. Uploads Reports --> F[Cloud Storage Bucket];
    end

    C -- 4. Invokes Worker --> D;
    G -- 7. Polls for Report --> F;
    F -- 8. Report Ready --> G;
```

## **Deployment Instructions** {#deployment-instructions}

Follow the **Common Prerequisites** first, then choose **Method 1** or **Method 2** to deploy.

### **Common Prerequisites (Required for all methods)** {#common-prerequisites-(required-for-all-methods)}

1. **Enable APIs**:  
   * A Google Cloud Project with billing enabled.  
   * [gcloud CLI](https://cloud.google.com/sdk/install) installed and authenticated (`gcloud auth login`).  
   * Run the following command to enable all necessary APIs:

| gcloud services enable \\    run.googleapis.com \\    cloudbuild.googleapis.com \\    cloudtasks.googleapis.com \\    iam.googleapis.com \\    cloudresourcemanager.googleapis.com \\    logging.googleapis.com \\    recommender.googleapis.com \\    securitycenter.googleapis.com \\    servicehealth.googleapis.com \\    essentialcontacts.googleapis.com \\    compute.googleapis.com \\    container.googleapis.com \\    sqladmin.googleapis.com \\    osconfig.googleapis.com \\    monitoring.googleapis.com \\    storage.googleapis.com \\    aiplatform.googleapis.com \\    cloudasset.googleapis.com |
| :---- |

   

   

2. **Create Service Account & Grant Permissions**:  
   * This SA will be used by the Cloud Run service to scan the organization and create tasks.

| \# Set your Organization IDexport ORG\_ID="\<your-org-id\>"\# Set Project and SA variablesexport PROJECT\_ID=$(gcloud config get-value project)export SA\_NAME="cloudgauge-sa"export SA\_EMAIL="${SA\_NAME}@${PROJECT\_ID}.iam.gserviceaccount.com"\# Create the Service Accountgcloud iam service-accounts create ${SA\_NAME} \--display-name="CloudGauge Service Account"\# \--- Grant Permissions \---\# 1\. Grant ORG-level roles to read assets and policiesgcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/browser"gcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/cloudasset.viewer"gcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/compute.networkViewer"gcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/essentialcontacts.viewer"gcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/recommender.iamViewer"gcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/logging.viewer"gcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/monitoring.viewer"gcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/orgpolicy.policyViewer"gcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/resourcemanager.organizationViewer"gcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/servicehealth.viewer"gcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/securitycenter.settingsViewer"gcloud organizations add-iam-policy-binding ${ORG\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/iam.securityReviewer"\# 2\. Grant PROJECT-level roles (on the project where Cloud Run is deployed)gcloud projects add-iam-policy-binding ${PROJECT\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/aiplatform.user"gcloud projects add-iam-policy-binding ${PROJECT\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/storage.objectCreator"gcloud projects add-iam-policy-binding ${PROJECT\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/storage.objectViewer"gcloud projects add-iam-policy-binding ${PROJECT\_ID} \--member="serviceAccount:${SA\_EMAIL}" \--role="roles/cloudtasks.admin"\# 3\. Service Account Token Creator and User role to the SA itself for signed URLsgcloud iam service-accounts add-iam-policy-binding ${SA\_EMAIL} \--member="serviceAccount:${SA\_EMAIL}"  \--role="roles/iam.serviceAccountTokenCreator" gcloud iam service-accounts add-iam-policy-binding ${SA\_EMAIL} \--member="serviceAccount:${SA\_EMAIL}"  \--role="roles/iam.serviceAccountUser" |
| :---- |

   

3. **Create GCS Bucket**:

| export BUCKET\_NAME="cloudgauge-reports-${PROJECT\_ID}"gsutil mb \-p ${PROJECT\_ID} gs://${BUCKET\_NAME} |
| :---- |

---

### 

### **Method 1: Deploy from Source (Recommended)** {#method-1:-deploy-from-source-(recommended)}

This is the simplest way to deploy. Cloud Run will build and deploy the service directly from this repository.

1. **Fork** this repository to your own GitHub account.  
2. In the Google Cloud Console, navigate to **Cloud Run** and click **Create Service**.  
3. Select **"Continuously deploy new revisions from a source repository"** and click **"Set up with Cloud Build"**. Connect your forked GitHub repository.  
4. In the build settings, select **"Dockerfile"** as the build type. The `Dockerfile` path should be `/Dockerfile`.  
5. Set the **Service name** (e.g., `cloudgauge-checker`) and select a **Region** (e.g., `asia-south1`).  
6. Under **"Container(s), Volumes, Networking, Security"**, go to the **"Identity & Security"** tab and select the Service Account you created (`cloudgauge-sa@...`).  
7. Go to the **"General"** tab and set the **Request Timeout** to `3600` seconds (1 hour).  
8. Go to the **"Variables & Secrets"** tab and add the following **Environment Variables**:  
   * `PROJECT_ID`: Your GCP Project ID (e.g., `my-gcp-project`)  
   * `TASK_QUEUE`: `cloudgauge-scan-queue`  
   * `RESULTS_BUCKET`: The bucket name you created (e.g., `cloudgauge-reports-my-gcp-project`)  
   * `SERVICE_ACCOUNT_EMAIL`: The SA email (e.g., `cloudgauge-sa@my-gcp-project.iam.gserviceaccount.com`)  
   * `LOCATION`: The region you chose (e.g., `asia-south1`)  
9. Click **Create**. The service will build and deploy. **The first deployment may fail or the app will not work correctly.** This is expected because the `WORKER_URL` is not yet set.  
10. **Grant Invoker Permission:** Once the service is created, you must grant its SA permission to invoke itself (for Cloud Tasks). Run the following command:  
    Bash

| gcloud run services add-iam-policy-binding cloudgauge-service \\  \--member="serviceAccount:${SA\_EMAIL}" \\  \--role="roles/run.invoker" \\  \--region=asia-south1 |
| :---- |

    

11. *Replace `cloudgauge-checker` and `asia-south1` if you used different values*  
12. **Update the Service:**  
    * Get the URL of your new service from the Cloud Run UI.  
    * Click **"Edit & Deploy New Revision"**.  
    * Go back to the **"Variables & Secrets"** tab and add **one more** environment variable:  
      * `WORKER_URL`: The URL of your service (e.g., `https://cloudgauge-checker-....run.app`)  
    * Click **Deploy**. This second revision will now function correctly.

---

### **Method 2: Manual Build & Deploy via gcloud** {#method-2:-manual-build-&-deploy-via-gcloud}

This method gives you manual control over the build and deploy steps.

1. **Clone this repository**:

| git clone https://github.com/your-username/cloudgauge.gitcd cloudgauge |
| :---- |

   

2. **Set Environment Variables**:  
   * (You should already have `PROJECT_ID` and `SA_EMAIL` from the common setup)

| export REGION\="asia-south1" \# Or your preferred regionexport SERVICE\_NAME\="cloudgauge-checker"export BUCKET\_NAME\="cloudgauge-reports-${PROJECT\_ID}"export QUEUE\_NAME\="cloudgauge-scan-queue" |
| :---- |

3. **Build and Deploy Service (Step 1 of 2\)**:  
   * This command builds the container and deploys it without the `WORKER_URL`.

| \# Build the container image using Cloud Buildgcloud builds submit . \--tag "gcr.io/${PROJECT\_ID}/${SERVICE\_NAME}"\# Deploy to Cloud Rungcloud run deploy ${SERVICE\_NAME} \\  \--image "gcr.io/${PROJECT\_ID}/${SERVICE\_NAME}" \\  \--service-account ${SA\_EMAIL} \\  \--region ${REGION} \\  \--allow-unauthenticated \\  \--platform managed \\  \--timeout\=3600 \\\--set-env-vars\=PROJECT\_ID=${PROJECT\_ID},TASK\_QUEUE\=${QUEUE\_NAME},RESULTS\_BUCKET=${BUCKET\_NAME},SERVICE\_ACCOUNT\_EMAIL\=${SA\_EMAIL},LOCATION=${REGION} |
| :---- |

4. **Grant Invoker Permission**:  
   * Now that the service exists, give its SA permission to invoke it.

| gcloud run services add-iam-policy-binding ${SERVICE\_NAME} \\  \--member\="serviceAccount:${SA\_EMAIL}" \\  \--role\="roles/run.invoker" \\  \--region\=${REGION} |
| :---- |

   

5. **Get Deployed Service URL**:

| export SERVICE\_URL=$(gcloud run services describe ${SERVICE\_NAME} \--platform managed \--region ${REGION} \--format 'value(status.url)')echo "Service URL is: ${SERVICE\_URL}" |
| :---- |

6. **Update Service with its Own URL (Step 2 of 2\)**:  
   * Update the service to provide it with its own URL, which Cloud Tasks will use.

| gcloud run services update ${SERVICE\_NAME} \\  \--platform managed \\  \--region ${REGION} \\  \--update-env-vars=WORKER\_URL=${SERVICE\_URL} |
| :---- |

Your service is now fully deployed and configured\!

## **How to Use** {#how-to-use}

1. Navigate to your service's URL (`${SERVICE_URL}`).  
2. Enter your Google Cloud Organization ID.  
3. Click "Start Scan".  
4. You will be redirected to a status page. Wait for the scan to complete (this can take 5-15 minutes depending on org size).  
5. Once finished, links to the **Interactive HTML Report** and **Download CSV Report** will appear.

## **Troubleshooting** {#troubleshooting}

If the status page is stuck for a long time, the background worker is likely failing.

### **Step 1: Check the Cloud Run Logs**

1. Go to the **Cloud Run** page in the Google Cloud Console.  
2. Click on your service (`cloudgauge-checker`).  
3. Go to the **LOGS** tab.  
4. Look for log entries for requests made to the `/run-scan` URL.  
5. If you see logs for `/run-scan`, look for any errors in red. Common errors are **permission denied** messages from APIs (e.g., `PERMISSION_DENIED on resource ...`). This means the Service Account is missing an IAM role.

### **Step 2: Check the Cloud Tasks Logs**

1. Go to the **Cloud Tasks** page in the Google Cloud Console.  
2. Click on your queue (`cloudgauge-scan-queue`).  
3. Go to the **LOGS** tab.  
4. Look at the status of the task attempts. If you see a `PERMISSION_DENIED` (HTTP 403\) error, it means you missed the **"Grant Invoker Permission"** step.

## **License & Support** {#license-&-support}

This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

This project is licensed under the Apache 2.0 License. See the `LICENSE` file for details.

For issues or feature requests, please file an issue on the project's GitHub page.

