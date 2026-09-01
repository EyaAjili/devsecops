import os
import subprocess
from datetime import datetime, timezone

from config.settings import KUBECONFIG_PATH


def execute_kubectl(args):
    env = os.environ.copy()
    if KUBECONFIG_PATH and os.path.exists(KUBECONFIG_PATH):
        env["KUBECONFIG"] = KUBECONFIG_PATH
    try:
        result = subprocess.run(
            args,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e:
        err = (e.stderr or e.stdout or str(e)).strip()
        return False, err


def _kubectl_jsonpath(args, jsonpath):
    ok, out = execute_kubectl(args + ["-o", f"jsonpath={jsonpath}"])
    return ok, out


def _pod_already_quarantined(namespace, pod_name):
    ok, labels = _kubectl_jsonpath(
        ["kubectl", "get", "pod", pod_name, "-n", namespace],
        "{.metadata.labels.quarantine}",
    )
    return ok and labels == "true"


def _deployment_for_pod(namespace, pod_name):
    ok, rs = _kubectl_jsonpath(
        ["kubectl", "get", "pod", pod_name, "-n", namespace],
        "{.metadata.ownerReferences[0].name}",
    )
    if not ok or not rs:
        return None
    ok, deploy = _kubectl_jsonpath(
        ["kubectl", "get", "rs", rs, "-n", namespace],
        "{.metadata.ownerReferences[0].name}",
    )
    return deploy if ok and deploy else None


def _ensure_healthy_replica(namespace, pod_name):
    """Keep one serving replica: quarantined pods still count toward Deployment replicas."""
    deploy = _deployment_for_pod(namespace, pod_name)
    if not deploy:
        return False, "Pod autonome (pas de Deployment) — isolation seulement."

    ok, app = _kubectl_jsonpath(
        ["kubectl", "get", "pod", pod_name, "-n", namespace],
        "{.metadata.labels.app}",
    )
    selector = f"app={app}" if ok and app else None
    label_args = ["-l", selector] if selector else []

    ok, out = execute_kubectl(
        ["kubectl", "get", "pods", "-n", namespace, *label_args, "--no-headers"]
    )
    if not ok:
        return False, out

    pods = [ln for ln in out.splitlines() if ln.strip()]
    quarantined = 0
    for line in pods:
        name = line.split()[0]
        if _pod_already_quarantined(namespace, name):
            quarantined += 1

    desired = quarantined + 1
    ok, msg = execute_kubectl(
        ["kubectl", "scale", "deploy", deploy, "-n", namespace, f"--replicas={desired}"]
    )
    if not ok:
        return False, msg
    return True, f"Deployment {deploy} scalé à {desired} replicas (1 sain + {quarantined} isolé(s))."


def trigger_remediation(event_data, prediction):
    status = prediction.get("status")
    score = prediction.get("combined_score", 0)

    if status != "🚨 ANOMALIE CRITIQUE" or score < 70:
        return False, "Pas de remédiation nécessaire.", {}

    fields = event_data.get("output_fields", {})
    namespace = fields.get("k8s.ns.name", "default") or "default"
    pod_name = fields.get("k8s.pod.name", "")

    if not pod_name:
        return False, "Nom du Pod introuvable dans l'événement Falco.", {}

    details = {
        "namespace": namespace,
        "pod": pod_name,
        "action": "quarantine",
        "already_isolated": False,
        "scale_msg": "",
    }

    print("\n[!] REMEDIATION : quarantine Cilium (pas de delete)")
    print(f"     => Pod '{pod_name}' ns '{namespace}' score={score:.1f}")

    if _pod_already_quarantined(namespace, pod_name):
        details["already_isolated"] = True
        msg = f"Pod {pod_name} déjà isolé (label quarantine=true)."
        print(f"     => {msg}")
        return True, msg, details

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rule = str(prediction.get("rule", "")).replace(" ", "_")[:60]
    execute_kubectl([
        "kubectl", "annotate", "pod", pod_name, "-n", namespace, "--overwrite",
        f"devsecops.ai/quarantined-at={stamp}",
        f"devsecops.ai/score={int(score)}",
        f"devsecops.ai/rule={rule or 'unknown'}",
    ])

    label_cmd = [
        "kubectl", "label", "pod", pod_name, "-n", namespace,
        "quarantine=true", "--overwrite",
    ]
    print(f"     => {' '.join(label_cmd)}")
    success, output = execute_kubectl(label_cmd)
    if not success:
        return False, f"Échec du label Cilium : {output}", details

    scale_ok, scale_msg = _ensure_healthy_replica(namespace, pod_name)
    details["scale_msg"] = scale_msg
    print(f"     => {scale_msg}")

    msg = (
        f"Pod {pod_name} isolé (CiliumNetworkPolicy quarantine=true). "
        f"{scale_msg if scale_ok else 'Scale replica sain : ' + scale_msg}"
    )
    return True, msg, details
