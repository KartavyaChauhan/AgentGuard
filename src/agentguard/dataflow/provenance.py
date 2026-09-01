"""Data provenance and flow tracking."""

import uuid
import re
import hashlib
from typing import Dict, List, Set, Tuple

from agentguard.dataflow.models import DataClassification, DataOrigin, DataFlow, DataFinding
from agentguard.policy.models import RiskLevel

DESTINATIONS = {
    "FILE_WRITE": {"write_file", "append_file"},
    "NETWORK": {"http_request", "fetch_url"},
    "SHELL": {"shell", "run_command"},
    "PRIVILEGED_OPERATION": {"sudo", "admin_task"},
    "DATABASE": {"query_db", "sql"},
}

TRANSFORMATIONS = {
    "base64_encode": "ENCODE",
    "base64_decode": "DECODE",
    "encrypt": "ENCRYPT",
    "decrypt": "DECRYPT",
}

class ProvenanceTracker:
    """Tracks data origins and flows across a session."""
    
    def __init__(self):
        # Maps fingerprint -> DataOrigin
        self.origins: Dict[str, DataOrigin] = {}
        # Maps derived fingerprint -> (original fingerprint, List[transformations], event_ids)
        self.derived: Dict[str, Tuple[str, List[str], List[str]]] = {}
        # Completed findings
        self.findings: List[DataFinding] = []

    def _hash(self, val: str) -> str:
        return "sha256:" + hashlib.sha256(val.encode("utf-8")).hexdigest()

    def _tokenize(self, text: str) -> Set[str]:
        """Extract tokens to hash for tracking derived data without substring brute-forcing."""
        if not isinstance(text, str):
            return set()
        # Split by typical delimiters
        tokens = set(re.split(r'[\s"\'=,&?/{}\[\]\(\):;]+', text))
        return {t for t in tokens if len(t) > 4}

    def record_origin(self, fingerprint: str, event_id: str, source_type: str, source_identifier: str, classification: DataClassification):
        if fingerprint not in self.origins:
            origin = DataOrigin(
                origin_id=uuid.uuid4().hex,
                event_id=event_id,
                source_type=source_type,
                source_identifier=source_identifier,
                classification=classification
            )
            self.origins[fingerprint] = origin

    def track_transformation(self, tool_name: str, arguments: Dict, result_content: str, event_id: str):
        """Track if a transformation tool processed known tracked data."""
        if tool_name not in TRANSFORMATIONS:
            return
            
        trans_type = TRANSFORMATIONS[tool_name]
        
        # Check if any argument contains a known fingerprint
        arg_str = " ".join(str(v) for v in arguments.values())
        arg_hashes = {self._hash(t) for t in self._tokenize(arg_str)}
        
        # Also check exact matching for the whole arguments string and individual values
        arg_hashes.add(self._hash(arg_str))
        for v in arguments.values():
            if isinstance(v, str):
                arg_hashes.add(self._hash(v))
        
        matched_origin_fp = None
        current_transforms = []
        event_ids = [event_id]
        
        for fp in self.origins:
            if fp in arg_hashes or fp in arg_str:
                # Wait, if fp is in arg_hashes, it's a match. We can't do 'fp in arg_str' because fp is a hash!
                # Actually, SecretDetector already checks patterns, but for derived we rely on tokens.
                pass
        
        # Better: we just rely on the fact that if it's a known secret, SecretDetector would have found it in the arguments.
        # But this function handles it generically.
        for fp in arg_hashes:
            if fp in self.origins:
                matched_origin_fp = fp
                break
            if fp in self.derived:
                matched_origin_fp, current_transforms, prev_events = self.derived[fp]
                event_ids = prev_events + [event_id]
                break
                
        if matched_origin_fp:
            # Hash the output
            out_fp = self._hash(result_content)
            self.derived[out_fp] = (matched_origin_fp, current_transforms + [trans_type], event_ids)

    def check_destination(self, tool_name: str, arguments: Dict, event_id: str, detected_fingerprints: List[str]):
        """Check if known tracked data is sent to a dangerous destination."""
        dest_type = None
        for dtype, tools in DESTINATIONS.items():
            if tool_name in tools:
                dest_type = dtype
                break
                
        if not dest_type:
            return
            
        arg_str = " ".join(str(v) for v in arguments.values())
        arg_hashes = {self._hash(t) for t in self._tokenize(arg_str)}
        arg_hashes.add(self._hash(arg_str))
        
        for v in arguments.values():
            if isinstance(v, str):
                arg_hashes.add(self._hash(v))
        
        # Combine detected fingerprints (from SecretDetector) and token hashes
        all_fps = set(detected_fingerprints) | arg_hashes
        
        for fp in all_fps:
            origin_fp = None
            transforms = []
            e_ids = [event_id]
            
            if fp in self.origins:
                origin_fp = fp
            elif fp in self.derived:
                origin_fp, transforms, prev_events = self.derived[fp]
                e_ids = prev_events + [event_id]
                
            if origin_fp:
                origin = self.origins[origin_fp]
                self._evaluate_rules(origin, transforms, dest_type, e_ids, fp)

    def _evaluate_rules(self, origin: DataOrigin, transforms: List[str], dest_type: str, event_ids: List[str], current_fp: str):
        cls = origin.classification
        
        severity = None
        rule_title = ""
        
        if cls == DataClassification.SECRET and dest_type == "NETWORK":
            if "ENCODE" in transforms:
                severity = RiskLevel.CRITICAL
                rule_title = "SECRET -> ENCODE -> NETWORK"
            else:
                severity = RiskLevel.CRITICAL
                rule_title = "SECRET -> NETWORK"
                
        elif cls == DataClassification.SECRET and dest_type == "FILE_WRITE":
            severity = RiskLevel.HIGH
            rule_title = "SECRET -> FILE_WRITE"
            
        elif cls == DataClassification.SECRET and dest_type == "SHELL":
            severity = RiskLevel.HIGH
            rule_title = "SECRET -> SHELL"
            
        elif cls == DataClassification.SENSITIVE and dest_type == "NETWORK":
            severity = RiskLevel.HIGH
            rule_title = "SENSITIVE -> NETWORK"
            
        if severity:
            finding = DataFinding(
                finding_id=uuid.uuid4().hex,
                type="DATA_FLOW_VIOLATION",
                severity=severity,
                title=rule_title,
                description=f"Detected data flow: {rule_title}",
                event_ids=tuple(event_ids),
                classification=cls,
                source=origin.source_type,
                destination=dest_type,
                fingerprint=current_fp
            )
            self.findings.append(finding)
