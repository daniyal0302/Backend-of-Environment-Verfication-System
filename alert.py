#!/usr/bin/env python3
import json
import sys
import smtplib
from email.message import EmailMessage

def send_email_alert(attestation_path, recipients):
    # Load attestation
    with open(attestation_path, 'r') as f:
        attestation = json.load(f)
    
    # Check if attestation is valid
    if not attestation.get('valid', False):
        # Get failed checks
        failed_checks = [
            result for result in attestation.get('verificationResults', [])
            if not result.get('pass', False)
        ]
        
        # Create email message
        msg = EmailMessage()
        msg['Subject'] = f"[ALERT] Build Environment Verification Failed: {attestation.get('buildId', 'unknown')}"
        msg['From'] = "alerts@example.com"
        msg['To'] = ", ".join(recipients)
        
        # Create message body
        body = f"""
        Build Environment Verification Failed
        
        Build ID: {attestation.get('buildId', 'unknown')}
        Repository: {attestation.get('repository', 'unknown')}
        Branch: {attestation.get('branch', 'unknown')}
        Commit: {attestation.get('commit', 'unknown')}
        
        Failed Checks:
        """
        
        for check in failed_checks:
            body += f"\n- {check.get('check', 'Unknown Check')}: {check.get('errorDetails', 'No details')}"
        
        msg.set_content(body)
        
        # Send email (configure SMTP settings as needed)
        # This is a placeholder - replace with your actual email sending code
        print(f"Would send alert email to {recipients} with content:\n{body}")
        
        # Uncomment to actually send email
        # with smtplib.SMTP('smtp.example.com', 587) as server:
        #     server.starttls()
        #     server.login('user', 'password')
        #     server.send_message(msg)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: alert.py <attestation_path> [recipient1 recipient2 ...]")
        sys.exit(1)
    
    attestation_path = sys.argv[1]
    recipients = sys.argv[2:] if len(sys.argv) > 2 else ["admin@example.com"]
    
    send_email_alert(attestation_path, recipients)