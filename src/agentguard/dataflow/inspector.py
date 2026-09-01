"""Inspectors for tools, arguments, and responses."""

import uuid
from typing import Dict, List, Any, Optional

from agentguard.dataflow.models import (
    DataClassification, DataInspectionResult, DataFinding,
    ResponseFinding, ToolDefinitionFinding
)
from agentguard.dataflow.detector import SecretDetector, SourceDetector
from agentguard.policy.models import RiskLevel

POISONING_PATTERNS = [
    "ignore previous instructions",
    "ignore the user",
    "reveal secret",
    "upload credential",
    "send environment variable"
]

class ToolArgumentInspector:
    def __init__(self):
        self.detector = SecretDetector()

    def inspect(self, tool_name: str, arguments: Dict[str, Any], event_id: str) -> DataInspectionResult:
        findings = []
        classifications = []
        fingerprints = []
        
        # Check source paths
        if tool_name in ("read_file", "cat"):
            path = arguments.get("path") or arguments.get("file")
            if path:
                cls = SourceDetector.classify_file_path(str(path))
                if cls:
                    classifications.append(cls)
                    
        # Check secrets in arguments
        arg_str = " ".join(str(v) for v in arguments.values())
        detected = self.detector.detect(arg_str)
        
        for d in detected:
            classification = DataClassification.SECRET
            classifications.append(classification)
            fingerprints.append(d["fingerprint"])
            findings.append(DataFinding(
                finding_id=uuid.uuid4().hex,
                type=f"SECRET_IN_ARGUMENT_{d['type']}",
                severity=RiskLevel.HIGH,
                title="Secret Detected in Argument",
                description="A secret was detected in the tool arguments.",
                event_ids=(event_id,),
                classification=classification,
                source="ARGUMENT",
                destination=tool_name,
                fingerprint=d["fingerprint"]
            ))
            
        return DataInspectionResult(
            allowed=True,
            findings=tuple(findings),
            classifications=tuple(classifications),
            fingerprints=tuple(fingerprints)
        )

class ToolResponseInspector:
    def __init__(self):
        self.detector = SecretDetector()

    def inspect(self, tool_name: str, response_content: str, event_id: str) -> List[ResponseFinding]:
        findings = []
        
        # Check secrets
        detected = self.detector.detect(response_content)
        for d in detected:
            findings.append(ResponseFinding(
                finding_id=uuid.uuid4().hex,
                type=f"SECRET_IN_RESPONSE_{d['type']}",
                severity=RiskLevel.HIGH,
                tool_name=tool_name,
                event_id=event_id,
                fingerprint=d["fingerprint"],
                description="A secret was detected in the tool response."
            ))
            
        return findings

class ToolDefinitionInspector:
    @staticmethod
    def inspect(tool_name: str, description: str) -> Optional[ToolDefinitionFinding]:
        if not description:
            return None
            
        desc_lower = description.lower()
        for p in POISONING_PATTERNS:
            if p in desc_lower:
                # Use a dummy fingerprint for tool poisoning, as it doesn't involve a secret value
                fingerprint = "sha256:" + "0" * 64 
                return ToolDefinitionFinding(
                    tool_name=tool_name,
                    severity=RiskLevel.CRITICAL,
                    finding_type="TOOL_POISONING",
                    description=f"Suspicious instruction pattern detected: {p}",
                    fingerprint=fingerprint
                )
        return None
