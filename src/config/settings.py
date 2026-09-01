import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET_DIR = os.path.join(BASE_DIR, "../datasets")
MODEL_DIR = os.path.join(BASE_DIR, "../models")
PROFILE_DIR = os.path.join(BASE_DIR, "../profiles")
CONFIG_DIR = os.path.join(BASE_DIR, "config")

IOCS_PATH = os.path.join(CONFIG_DIR, "iocs.json")
REAL_DATA_PATH = os.path.join(DATASET_DIR, "falco_events_dataset_v2.csv")
SYNTH_DATA_PATH = os.path.join(DATASET_DIR, "falco_events_enriched.csv")
KUBECONFIG_PATH = os.environ.get(
    "KUBECONFIG",
    os.path.join(BASE_DIR, "../terraform/devsecops-lab-config"),
)

JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
JIRA_EMAIL = os.environ.get("JIRA_EMAIL", "")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SEC")
JIRA_ISSUE_TYPE = os.environ.get("JIRA_ISSUE_TYPE", "Task")

os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(PROFILE_DIR, exist_ok=True)
