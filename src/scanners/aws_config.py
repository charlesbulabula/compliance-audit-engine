import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

CONTROL_MAP: Dict[str, List[str]] = {
    "access-keys-rotated": ["CIS_1.14", "SOC2_CC6.1"],
    "mfa-enabled-for-iam-console-access": ["CIS_1.10", "SOC2_CC6.2", "PCI_DSS_8.4"],
    "root-account-mfa-enabled": ["CIS_1.5", "SOC2_CC6.2", "PCI_DSS_8.4"],
    "s3-bucket-public-read-prohibited": ["CIS_2.1.5", "SOC2_CC6.3", "PCI_DSS_1.3"],
    "s3-bucket-public-write-prohibited": ["CIS_2.1.5", "SOC2_CC6.3", "PCI_DSS_1.3"],
    "s3-bucket-ssl-requests-only": ["CIS_2.1.2", "PCI_DSS_4.1"],
    "s3-bucket-server-side-encryption-enabled": ["CIS_2.1.1", "SOC2_CC6.7", "PCI_DSS_3.4"],
    "cloudtrail-enabled": ["CIS_3.1", "SOC2_CC7.2", "PCI_DSS_10.1"],
    "cloudtrail-s3-dataevents-enabled": ["CIS_3.3", "SOC2_CC7.2"],
    "vpc-flow-logs-enabled": ["CIS_3.9", "SOC2_CC7.2", "PCI_DSS_10.6"],
    "restricted-ssh": ["CIS_5.2", "SOC2_CC6.6", "PCI_DSS_1.2"],
    "restricted-common-ports": ["CIS_5.1", "SOC2_CC6.6"],
    "iam-password-policy": ["CIS_1.8", "SOC2_CC6.1", "PCI_DSS_8.3"],
    "iam-root-access-key-check": ["CIS_1.4", "SOC2_CC6.2"],
    "ebs-snapshot-public-restorable-check": ["CIS_2.2.1", "SOC2_CC6.3"],
    "rds-instance-public-access-check": ["CIS_2.3.2", "SOC2_CC6.6"],
    "kms-cmk-not-scheduled-for-deletion": ["CIS_2.8", "SOC2_CC6.7"],
    "guardduty-enabled-centralized": ["SOC2_CC7.1", "PCI_DSS_11.5"],
    "securityhub-enabled": ["SOC2_CC7.1"],
    "ec2-imdsv2-check": ["CIS_5.6", "SOC2_CC6.6"],
}

RULE_SEVERITY: Dict[str, str] = {
    "root-account-mfa-enabled": "CRITICAL",
    "iam-root-access-key-check": "CRITICAL",
    "cloudtrail-enabled": "HIGH",
    "s3-bucket-public-read-prohibited": "HIGH",
    "s3-bucket-public-write-prohibited": "HIGH",
    "vpc-flow-logs-enabled": "MEDIUM",
    "restricted-ssh": "HIGH",
    "ebs-snapshot-public-restorable-check": "HIGH",
    "rds-instance-public-access-check": "HIGH",
}


@dataclass
class Finding:
    rule_name: str
    resource_id: str
    resource_type: str
    severity: str
    control_ids: List[str]
    account_id: str
    region: str
    compliance_type: str = "NON_COMPLIANT"
    annotation: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_name": self.rule_name,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "severity": self.severity,
            "control_ids": self.control_ids,
            "account_id": self.account_id,
            "region": self.region,
            "compliance_type": self.compliance_type,
            "annotation": self.annotation,
        }


class AWSConfigScanner:
    def __init__(self, session: boto3.Session):
        self._session = session
        self._config_client = session.client("config")
        self._region = session.region_name or "us-east-1"
        sts = session.client("sts")
        try:
            identity = sts.get_caller_identity()
            self._account_id = identity["Account"]
        except Exception as exc:
            logger.warning("Could not determine account ID: %s", exc)
            self._account_id = "unknown"
        logger.info("AWSConfigScanner initialized: account=%s region=%s", self._account_id, self._region)

    def get_noncompliant_rules(self, account_id: Optional[str] = None) -> List[str]:
        effective_account = account_id or self._account_id
        noncompliant_rules = []
        paginator = self._config_client.get_paginator("describe_compliance_by_config_rule")

        try:
            for page in paginator.paginate(ComplianceTypes=["NON_COMPLIANT"]):
                for rule_compliance in page.get("ComplianceByConfigRules", []):
                    rule_name = rule_compliance["ConfigRuleName"]
                    noncompliant_rules.append(rule_name)
            logger.info("Found %d non-compliant rules in account %s", len(noncompliant_rules), effective_account)
        except (ClientError, BotoCoreError) as exc:
            logger.error("Failed to describe compliance by config rule: %s", exc)
            raise

        return noncompliant_rules

    def get_noncompliant_resources(self, rule_name: str) -> List[Finding]:
        findings = []
        control_ids = CONTROL_MAP.get(rule_name, [])
        severity = RULE_SEVERITY.get(rule_name, "MEDIUM")
        paginator = self._config_client.get_paginator("get_compliance_details_by_config_rule")

        try:
            for page in paginator.paginate(
                ConfigRuleName=rule_name,
                ComplianceTypes=["NON_COMPLIANT"],
            ):
                for result in page.get("EvaluationResults", []):
                    qualifier = result.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {})
                    resource_id = qualifier.get("ResourceId", "unknown")
                    resource_type = qualifier.get("ResourceType", "unknown")
                    annotation = result.get("Annotation")

                    finding = Finding(
                        rule_name=rule_name,
                        resource_id=resource_id,
                        resource_type=resource_type,
                        severity=severity,
                        control_ids=control_ids,
                        account_id=self._account_id,
                        region=self._region,
                        compliance_type="NON_COMPLIANT",
                        annotation=annotation,
                    )
                    findings.append(finding)
        except (ClientError, BotoCoreError) as exc:
            logger.error("Failed to get compliance details for rule %s: %s", rule_name, exc)
            raise

        logger.info("Rule '%s': %d non-compliant resources", rule_name, len(findings))
        return findings

    def scan_all(self) -> List[Finding]:
        all_findings = []
        noncompliant_rules = self.get_noncompliant_rules()
        for rule_name in noncompliant_rules:
            try:
                findings = self.get_noncompliant_resources(rule_name)
                all_findings.extend(findings)
            except Exception as exc:
                logger.error("Skipping rule %s due to error: %s", rule_name, exc)
        logger.info("Scan complete: %d total findings across %d rules", len(all_findings), len(noncompliant_rules))
        return all_findings

# _r 20260529141804-41cf0fa8
