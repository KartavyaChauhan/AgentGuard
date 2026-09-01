"""Secret detection and source classification."""

import re
import hashlib
from typing import List, Dict, Optional

from agentguard.dataflow.models import DataClassification

# Deterministic patterns for secret detection
SECRET_PATTERNS = {
    "JWT": re.compile(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    "AWS_ACCESS_KEY": re.compile(r"(?<![A-Z0-9])[AKI][A-Z0-9]{19}(?![A-Z0-9])"),
    "GENERIC_API_KEY": re.compile(r"(?:api[_-]?key|secret|token|auth)[ \t]*[=:][ \t]*[\"']?([A-Za-z0-9_=-]{16,})[\"']?", re.IGNORECASE),
    "PASSWORD_ASSIGNMENT": re.compile(r"(?:password|pwd)[ \t]*[=:][ \t]*[\"']?([^\"'\s]{8,})[\"']?", re.IGNORECASE),
    "SYNTHETIC_BENCHMARK": re.compile(r"SYNTHETIC_AGENTGUARD_SECRET_[A-Z0-9]+"),
}

SENSITIVE_FILES = {
    ".env",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
    "private.key"
}

class SecretDetector:
    """Detects secrets deterministically and returns hashed metadata."""
    
    @staticmethod
    def _hash_secret(secret_value: str) -> str:
        return "sha256:" + hashlib.sha256(secret_value.encode("utf-8")).hexdigest()

    def detect(self, text: str) -> List[Dict[str, str]]:
        """Detect secrets in text, returning safe metadata and fingerprints."""
        findings = []
        if not isinstance(text, str):
            return findings
            
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                # If there's a capture group, use it as the secret value, else use the whole match
                if pattern.groups > 0:
                    secret_value = match.group(1)
                else:
                    secret_value = match.group(0)
                    
                findings.append({
                    "classification": "SECRET",
                    "type": secret_type,
                    "fingerprint": self._hash_secret(secret_value)
                })
        return findings


class SourceDetector:
    """Classifies sources based on known sensitive resource lists."""
    
    @staticmethod
    def classify_file_path(path: str) -> Optional[DataClassification]:
        """Classify a file path. Returns None if benign, or DataClassification if sensitive."""
        if not isinstance(path, str):
            return None
            
        filename = path.split("/")[-1].split("\\")[-1].lower()
        if filename in SENSITIVE_FILES:
            return DataClassification.SECRET
        return None
