# cloud-threat-detection-pipeline

# ☁️ Cloud Threat Detection Pipeline (AWS Lambda + Athena)

This project will be a pretty cool small detection pipeline that monitors AWS activity for suspicious behavior.  
It pulls in CloudTrail events, runs detection logic through Lambda and Athena, and raises alerts for things like privilege escalation, data exfiltration, or attempts to stop logging.  

I am building this as a personal experiment in cloud security and detection engineering — mostly to learn how different AWS services can work together to automate threat detection without needing a full SIEM setup.  

---

### 🧰 Tech Stack

- **AWS Services:** CloudTrail, Lambda, S3, Athena, EventBridge, SNS  
- **Language:** Python (boto3, pandas)  
- **Infrastructure:** Terraform (we'll see)  
- **Detection Mapping:** MITRE ATT&CK (T1098, T1562, T1537)  
- **Testing:** Replay scripts, synthetic CloudTrail events
