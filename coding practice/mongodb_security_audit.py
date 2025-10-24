#!/usr/bin/env python3
"""
MongoDB Security Audit Tool
A comprehensive toolkit for auditing MongoDB deployments for security misconfigurations.
"""

import argparse
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import pymongo
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, OperationFailure
import ssl
import socket
import subprocess
import platform
import os
from dataclasses import dataclass
from enum import Enum
import colorama
from colorama import Fore, Back, Style

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

class SecurityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class SecurityIssue:
    level: SecurityLevel
    category: str
    title: str
    description: str
    recommendation: str
    affected_components: List[str]
    cve_references: List[str] = None

class MongoDBSecurityAudit:
    def __init__(self, connection_string: str, username: str = None, password: str = None):
        self.connection_string = connection_string
        self.username = username
        self.password = password
        self.client = None
        self.issues = []
        self.security_score = 100
        self.audit_timestamp = datetime.now()
        
    def connect(self) -> bool:
        """Establish connection to MongoDB instance"""
        try:
            if self.username and self.password:
                self.client = MongoClient(
                    self.connection_string,
                    username=self.username,
                    password=self.password,
                    serverSelectionTimeoutMS=5000
                )
            else:
                self.client = MongoClient(
                    self.connection_string,
                    serverSelectionTimeoutMS=5000
                )
            
            # Test connection
            self.client.admin.command('ping')
            return True
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to connect to MongoDB: {e}")
            return False
    
    def check_tls_ssl(self) -> None:
        """Check if TLS/SSL is enabled"""
        try:
            # Check if connection is encrypted
            if self.client._topology._description.connected:
                # This is a simplified check - in practice, you'd need to check the connection details
                if not self.connection_string.startswith('mongodb+srv://') and 'ssl=true' not in self.connection_string:
                    self.issues.append(SecurityIssue(
                        level=SecurityLevel.CRITICAL,
                        category="Encryption",
                        title="TLS/SSL Not Enabled",
                        description="MongoDB connection is not using TLS/SSL encryption",
                        recommendation="Enable TLS/SSL by adding ?ssl=true to connection string or use mongodb+srv://",
                        affected_components=["Network", "Data Transmission"]
                    ))
        except Exception as e:
            self.issues.append(SecurityIssue(
                level=SecurityLevel.HIGH,
                category="Encryption",
                title="TLS/SSL Check Failed",
                description=f"Could not verify TLS/SSL status: {e}",
                recommendation="Manually verify TLS/SSL configuration",
                affected_components=["Network", "Data Transmission"]
            ))
    
    def check_authentication(self) -> None:
        """Check authentication configuration"""
        try:
            # Check if authentication is required
            result = self.client.admin.command("getParameter", "authenticationMechanisms")
            auth_mechanisms = result.get("authenticationMechanisms", [])
            
            if not auth_mechanisms:
                self.issues.append(SecurityIssue(
                    level=SecurityLevel.CRITICAL,
                    category="Authentication",
                    title="No Authentication Mechanisms",
                    description="No authentication mechanisms are configured",
                    recommendation="Enable authentication with SCRAM-SHA-256 or other secure mechanisms",
                    affected_components=["Authentication", "Access Control"]
                ))
            
            # Check for weak authentication mechanisms
            if "MONGODB-CR" in auth_mechanisms:
                self.issues.append(SecurityIssue(
                    level=SecurityLevel.HIGH,
                    category="Authentication",
                    title="Weak Authentication Mechanism",
                    description="MONGODB-CR is deprecated and considered weak",
                    recommendation="Use SCRAM-SHA-256 instead of MONGODB-CR",
                    affected_components=["Authentication"]
                ))
                
        except Exception as e:
            self.issues.append(SecurityIssue(
                level=SecurityLevel.MEDIUM,
                category="Authentication",
                title="Authentication Check Failed",
                description=f"Could not verify authentication configuration: {e}",
                recommendation="Manually verify authentication settings",
                affected_components=["Authentication"]
            ))
    
    def check_network_bindings(self) -> None:
        """Check network binding configuration"""
        try:
            # This would typically require access to MongoDB configuration files
            # For cloud instances, this check might not be applicable
            result = self.client.admin.command("getParameter", "bind_ip")
            bind_ip = result.get("bind_ip", "")
            
            if bind_ip == "0.0.0.0":
                self.issues.append(SecurityIssue(
                    level=SecurityLevel.CRITICAL,
                    category="Network Security",
                    title="Open Network Binding",
                    description="MongoDB is bound to all interfaces (0.0.0.0)",
                    recommendation="Bind MongoDB to specific IP addresses only",
                    affected_components=["Network", "Access Control"]
                ))
        except Exception as e:
            # This is expected for cloud instances
            pass
    
    def check_default_ports(self) -> None:
        """Check if default ports are being used"""
        try:
            # Extract port from connection string
            if ":" in self.connection_string and "mongodb+srv://" not in self.connection_string:
                port = self.connection_string.split(":")[-1].split("/")[0]
                if port == "27017":
                    self.issues.append(SecurityIssue(
                        level=SecurityLevel.MEDIUM,
                        category="Network Security",
                        title="Default Port in Use",
                        description="MongoDB is using the default port 27017",
                        recommendation="Consider using a non-standard port for additional security",
                        affected_components=["Network"]
                    ))
        except Exception:
            pass
    
    def check_encryption_at_rest(self) -> None:
        """Check if encryption at rest is enabled"""
        try:
            # This check is complex and depends on the MongoDB version and configuration
            # For now, we'll provide a general recommendation
            self.issues.append(SecurityIssue(
                level=SecurityLevel.HIGH,
                category="Encryption",
                title="Encryption at Rest Not Verified",
                description="Could not verify if encryption at rest is enabled",
                recommendation="Ensure WiredTiger encryption is enabled for sensitive data",
                affected_components=["Data Storage"]
            ))
        except Exception:
            pass
    
    def check_user_privileges(self) -> None:
        """Check for excessive user privileges"""
        try:
            users = self.client.admin.command("usersInfo")
            for user in users.get("users", []):
                roles = user.get("roles", [])
                for role in roles:
                    if role.get("role") == "root":
                        self.issues.append(SecurityIssue(
                            level=SecurityLevel.HIGH,
                            category="Access Control",
                            title="Root User Detected",
                            description=f"User '{user.get('user')}' has root privileges",
                            recommendation="Use principle of least privilege - assign specific roles instead of root",
                            affected_components=["Access Control", "User Management"]
                        ))
        except Exception as e:
            self.issues.append(SecurityIssue(
                level=SecurityLevel.MEDIUM,
                category="Access Control",
                title="User Privilege Check Failed",
                description=f"Could not verify user privileges: {e}",
                recommendation="Manually review user roles and privileges",
                affected_components=["Access Control"]
            ))
    
    def check_audit_logging(self) -> None:
        """Check if audit logging is enabled"""
        try:
            result = self.client.admin.command("getParameter", "auditLog")
            if not result.get("auditLog", {}).get("destination"):
                self.issues.append(SecurityIssue(
                    level=SecurityLevel.MEDIUM,
                    category="Logging",
                    title="Audit Logging Not Enabled",
                    description="Audit logging is not configured",
                    recommendation="Enable audit logging to track database activities",
                    affected_components=["Logging", "Compliance"]
                ))
        except Exception:
            self.issues.append(SecurityIssue(
                level=SecurityLevel.MEDIUM,
                category="Logging",
                title="Audit Logging Check Failed",
                description="Could not verify audit logging configuration",
                recommendation="Manually verify audit logging settings",
                affected_components=["Logging"]
            ))
    
    def check_replica_set_security(self) -> None:
        """Check replica set security configuration"""
        try:
            status = self.client.admin.command("replSetGetStatus")
            if status.get("ok") == 1:
                # Check if internal authentication is enabled
                config = self.client.admin.command("replSetGetConfig")
                if not config.get("config", {}).get("settings", {}).get("replicaSetId"):
                    self.issues.append(SecurityIssue(
                        level=SecurityLevel.HIGH,
                        category="Replica Set Security",
                        title="Replica Set ID Not Set",
                        description="Replica set ID is not configured",
                        recommendation="Set a unique replica set ID for security",
                        affected_components=["Replica Set", "Security"]
                    ))
        except Exception:
            pass
    
    def calculate_security_score(self) -> int:
        """Calculate overall security score based on identified issues"""
        score = 100
        for issue in self.issues:
            if issue.level == SecurityLevel.CRITICAL:
                score -= 25
            elif issue.level == SecurityLevel.HIGH:
                score -= 15
            elif issue.level == SecurityLevel.MEDIUM:
                score -= 10
            elif issue.level == SecurityLevel.LOW:
                score -= 5
        
        return max(0, score)
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive security audit report"""
        self.security_score = self.calculate_security_score()
        
        report = {
            "audit_metadata": {
                "timestamp": self.audit_timestamp.isoformat(),
                "connection_string": self.connection_string,
                "total_issues": len(self.issues),
                "security_score": self.security_score
            },
            "issues_by_severity": {
                "critical": [issue for issue in self.issues if issue.level == SecurityLevel.CRITICAL],
                "high": [issue for issue in self.issues if issue.level == SecurityLevel.HIGH],
                "medium": [issue for issue in self.issues if issue.level == SecurityLevel.MEDIUM],
                "low": [issue for issue in self.issues if issue.level == SecurityLevel.LOW],
                "info": [issue for issue in self.issues if issue.level == SecurityLevel.INFO]
            },
            "issues_by_category": {},
            "recommendations": self._generate_recommendations(),
            "next_steps": self._generate_next_steps()
        }
        
        # Group issues by category
        for issue in self.issues:
            category = issue.category
            if category not in report["issues_by_category"]:
                report["issues_by_category"][category] = []
            report["issues_by_category"][category].append(issue)
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        critical_issues = [issue for issue in self.issues if issue.level == SecurityLevel.CRITICAL]
        if critical_issues:
            recommendations.append("🚨 IMMEDIATE ACTION REQUIRED: Address all critical security issues")
        
        high_issues = [issue for issue in self.issues if issue.level == SecurityLevel.HIGH]
        if high_issues:
            recommendations.append("⚠️ HIGH PRIORITY: Resolve high-severity security issues within 48 hours")
        
        if any(issue.category == "Encryption" for issue in self.issues):
            recommendations.append("🔐 Enable TLS/SSL encryption for all connections")
        
        if any(issue.category == "Authentication" for issue in self.issues):
            recommendations.append("🔑 Implement strong authentication mechanisms")
        
        if any(issue.category == "Access Control" for issue in self.issues):
            recommendations.append("👥 Review and implement principle of least privilege")
        
        return recommendations
    
    def _generate_next_steps(self) -> List[str]:
        """Generate actionable next steps"""
        steps = [
            "Review the detailed security audit report",
            "Prioritize fixes based on severity levels",
            "Implement recommended security measures",
            "Schedule regular security audits",
            "Consider implementing MongoDB Field-Level Encryption (FLE) for sensitive data",
            "Set up monitoring and alerting for security events"
        ]
        return steps
    
    def print_colored_report(self, report: Dict[str, Any]) -> None:
        """Print a color-coded security audit report"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}MongoDB Security Audit Report")
        print(f"{Fore.CYAN}{'='*80}")
        
        # Audit metadata
        metadata = report["audit_metadata"]
        print(f"\n{Fore.YELLOW}📊 Audit Summary:")
        print(f"   Timestamp: {metadata['timestamp']}")
        print(f"   Connection: {metadata['connection_string']}")
        print(f"   Total Issues: {metadata['total_issues']}")
        
        # Security score with color coding
        score = metadata['security_score']
        if score >= 80:
            score_color = Fore.GREEN
        elif score >= 60:
            score_color = Fore.YELLOW
        else:
            score_color = Fore.RED
        
        print(f"   Security Score: {score_color}{score}/100{Style.RESET_ALL}")
        
        # Issues by severity
        print(f"\n{Fore.YELLOW}🔍 Security Issues by Severity:")
        for severity, issues in report["issues_by_severity"].items():
            if issues:
                if severity == "critical":
                    color = Fore.RED
                    icon = "🚨"
                elif severity == "high":
                    color = Fore.MAGENTA
                    icon = "⚠️"
                elif severity == "medium":
                    color = Fore.YELLOW
                    icon = "⚡"
                elif severity == "low":
                    color = Fore.BLUE
                    icon = "ℹ️"
                else:
                    color = Fore.CYAN
                    icon = "📝"
                
                print(f"\n{color}{icon} {severity.upper()} ({len(issues)} issues):{Style.RESET_ALL}")
                for issue in issues:
                    print(f"   • {issue.title}")
                    print(f"     Category: {issue.category}")
                    print(f"     Description: {issue.description}")
                    print(f"     Recommendation: {issue.recommendation}")
                    if issue.affected_components:
                        print(f"     Affected: {', '.join(issue.affected_components)}")
                    print()
        
        # Recommendations
        print(f"\n{Fore.GREEN}💡 Recommendations:")
        for i, rec in enumerate(report["recommendations"], 1):
            print(f"   {i}. {rec}")
        
        # Next steps
        print(f"\n{Fore.BLUE}📋 Next Steps:")
        for i, step in enumerate(report["next_steps"], 1):
            print(f"   {i}. {step}")
        
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}End of Report")
        print(f"{Fore.CYAN}{'='*80}\n")
    
    def run_audit(self) -> Dict[str, Any]:
        """Run complete security audit"""
        print(f"{Fore.CYAN}🔍 Starting MongoDB Security Audit...")
        
        if not self.connect():
            return None
        
        print(f"{Fore.GREEN}✅ Connected to MongoDB successfully")
        
        # Run all security checks
        checks = [
            self.check_tls_ssl,
            self.check_authentication,
            self.check_network_bindings,
            self.check_default_ports,
            self.check_encryption_at_rest,
            self.check_user_privileges,
            self.check_audit_logging,
            self.check_replica_set_security
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                print(f"{Fore.YELLOW}⚠️ Warning: {check.__name__} failed: {e}")
        
        # Generate and return report
        report = self.generate_report()
        self.print_colored_report(report)
        
        return report

def main():
    parser = argparse.ArgumentParser(description="MongoDB Security Audit Tool")
    parser.add_argument("connection_string", help="MongoDB connection string")
    parser.add_argument("-u", "--username", help="MongoDB username")
    parser.add_argument("-p", "--password", help="MongoDB password")
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    parser.add_argument("--json-only", action="store_true", help="Output only JSON report")
    
    args = parser.parse_args()
    
    # Create audit instance
    audit = MongoDBSecurityAudit(
        connection_string=args.connection_string,
        username=args.username,
        password=args.password
    )
    
    # Run audit
    report = audit.run_audit()
    
    if report and args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"{Fore.GREEN}📄 Report saved to {args.output}")
    
    if args.json_only and report:
        print(json.dumps(report, indent=2, default=str))

if __name__ == "__main__":
    main()
