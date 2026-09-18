import os
from dotenv import load_dotenv

load_dotenv()

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
REMEDIATION_ENABLED = os.getenv("REMEDIATION_ENABLED", "false").lower() == "true"
REPORT_DIR = os.getenv("REPORT_DIR", "reports")
IAM_KEY_MAX_AGE_DAYS = int(os.getenv("IAM_KEY_MAX_AGE_DAYS", "90"))
