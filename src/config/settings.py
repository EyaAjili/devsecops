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

# Webhook partagé Falcosidekick → collector (vide = pas d'auth, mode lab).
FALCO_WEBHOOK_TOKEN = os.environ.get("FALCO_WEBHOOK_TOKEN", "")
COLLECTOR_BIND_HOST = os.environ.get("COLLECTOR_BIND_HOST", "0.0.0.0")
COLLECTOR_WEBHOOK_PORT = int(os.environ.get("COLLECTOR_WEBHOOK_PORT", "5002"))
COLLECTOR_METRICS_PORT = int(os.environ.get("COLLECTOR_METRICS_PORT", "8000"))
HISTORY_MAX_ROWS = int(os.environ.get("HISTORY_MAX_ROWS", "50000"))

JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
JIRA_EMAIL = os.environ.get("JIRA_EMAIL", "")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SEC")
JIRA_ISSUE_TYPE = os.environ.get("JIRA_ISSUE_TYPE", "Task")





INCIDENT_DIR = os.getenv("INCIDENT_DIR", "data/incidents")
JENKINS_URL = os.getenv("JENKINS_URL", "")            # empty = Jenkins disabled
JENKINS_USER = os.getenv("JENKINS_USER", "")
JENKINS_TOKEN = os.getenv("JENKINS_TOKEN", "")
JENKINS_JOB = os.getenv("JENKINS_JOB", "security-incident-response")
COLLECTOR_PUBLIC_URL = os.getenv("COLLECTOR_PUBLIC_URL", "")  # how Jenkins pods reach the collector

FALCO_CSV_COLUMNS = [
    "timestamp", "uuid", "priority", "rule", "event_scope", "node", "namespace",
    "pod", "container_id", "container_name", "image", "image_tag", "user",
    "user_uid", "proc_name", "proc_exepath", "parent_process", "command",
    "event_type", "file", "connection", "command_duration_ms",
]

os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(PROFILE_DIR, exist_ok=True)
