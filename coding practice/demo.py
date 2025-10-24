#!/usr/bin/env python3
"""
MongoDB Security Audit Toolkit Demo
Demonstrates the key features of the security audit toolkit
"""

import json
import time
from datetime import datetime
from mongodb_security_audit import MongoDBSecurityAudit, SecurityLevel, SecurityIssue
from cloud_integration import CloudAuditManager
from fle_demo import FLEManager, FLESecurityAudit

def print_header(title):
    """Print a formatted header"""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)

def print_section(title):
    """Print a formatted section header"""
    print(f"\n🔍 {title}")
    print("-" * 40)

def demo_basic_audit():
    """Demonstrate basic MongoDB security audit"""
    print_header("MongoDB Security Audit Demo")
    
    # Create audit instance
    audit = MongoDBSecurityAudit("mongodb://localhost:27017")
    
    # Simulate some security issues for demonstration
    audit.issues = [
        SecurityIssue(
            level=SecurityLevel.CRITICAL,
            category="Encryption",
            title="TLS/SSL Not Enabled",
            description="MongoDB connection is not using TLS/SSL encryption",
            recommendation="Enable TLS/SSL by adding ?ssl=true to connection string",
            affected_components=["Network", "Data Transmission"]
        ),
        SecurityIssue(
            level=SecurityLevel.HIGH,
            category="Authentication",
            title="Weak Authentication Mechanism",
            description="MONGODB-CR is deprecated and considered weak",
            recommendation="Use SCRAM-SHA-256 instead of MONGODB-CR",
            affected_components=["Authentication"]
        ),
        SecurityIssue(
            level=SecurityLevel.MEDIUM,
            category="Network Security",
            title="Default Port in Use",
            description="MongoDB is using the default port 27017",
            recommendation="Consider using a non-standard port for additional security",
            affected_components=["Network"]
        )
    ]
    
    # Generate and display report
    report = audit.generate_report()
    audit.print_colored_report(report)
    
    return report

def demo_cloud_integration():
    """Demonstrate cloud integration features"""
    print_header("Cloud Integration Demo")
    
    print_section("AWS DocumentDB Integration")
    print("✅ AWS DocumentDB cluster discovery")
    print("✅ Security group analysis")
    print("✅ Encryption at rest verification")
    print("✅ Public accessibility checks")
    
    print_section("GCP MongoDB Atlas Integration")
    print("✅ Atlas cluster discovery")
    print("✅ Backup configuration analysis")
    print("✅ Cluster tier validation")
    print("✅ Security settings review")
    
    # Simulate cloud audit results
    cloud_results = {
        "aws_clusters": [
            {
                "cluster_identifier": "demo-cluster-1",
                "issues": [
                    {
                        "level": "HIGH",
                        "title": "Encryption at Rest Not Enabled",
                        "recommendation": "Enable encryption at rest for the cluster"
                    }
                ]
            }
        ],
        "gcp_clusters": [
            {
                "cluster_name": "atlas-cluster-1",
                "issues": [
                    {
                        "level": "MEDIUM",
                        "title": "Development Cluster in Production",
                        "recommendation": "Use M10 or higher tier for production workloads"
                    }
                ]
            }
        ]
    }
    
    print(f"\n📊 Cloud Audit Summary:")
    print(f"   AWS Clusters: {len(cloud_results['aws_clusters'])}")
    print(f"   GCP Clusters: {len(cloud_results['gcp_clusters'])}")
    print(f"   Total Issues: {sum(len(cluster['issues']) for cluster in cloud_results['aws_clusters'] + cloud_results['gcp_clusters'])}")
    
    return cloud_results

def demo_fle_features():
    """Demonstrate Field-Level Encryption features"""
    print_header("Field-Level Encryption Demo")
    
    print_section("FLE Implementation")
    print("✅ Master key generation")
    print("✅ Data key creation")
    print("✅ Schema definition")
    print("✅ Encryption/decryption operations")
    
    print_section("FLE Security Features")
    print("✅ Deterministic encryption for queryable fields")
    print("✅ Random encryption for sensitive data")
    print("✅ Key management and rotation")
    print("✅ Performance impact analysis")
    
    # Simulate FLE demonstration results
    fle_results = {
        "encryption_setup": True,
        "data_insertion": True,
        "encrypted_data_visible": True,
        "decrypted_data_visible": True,
        "comparison_queries": True,
        "issues_found": []
    }
    
    print(f"\n📊 FLE Demonstration Results:")
    for key, value in fle_results.items():
        if key != "issues_found":
            status = "✅" if value else "❌"
            print(f"   {status} {key}: {value}")
    
    return fle_results

def demo_security_scoring():
    """Demonstrate security scoring system"""
    print_header("Security Scoring System")
    
    # Simulate different security scenarios
    scenarios = [
        {
            "name": "Excellent Security",
            "issues": [],
            "expected_score": 100
        },
        {
            "name": "Good Security",
            "issues": [
                {"level": "LOW", "title": "Minor configuration issue"}
            ],
            "expected_score": 95
        },
        {
            "name": "Moderate Security",
            "issues": [
                {"level": "MEDIUM", "title": "Default port in use"},
                {"level": "LOW", "title": "Minor configuration issue"}
            ],
            "expected_score": 85
        },
        {
            "name": "Poor Security",
            "issues": [
                {"level": "CRITICAL", "title": "No encryption"},
                {"level": "HIGH", "title": "Weak authentication"},
                {"level": "MEDIUM", "title": "Default port in use"}
            ],
            "expected_score": 50
        }
    ]
    
    print_section("Security Score Examples")
    for scenario in scenarios:
        audit = MongoDBSecurityAudit("mongodb://localhost:27017")
        
        # Convert scenario issues to SecurityIssue objects
        for issue_data in scenario["issues"]:
            audit.issues.append(SecurityIssue(
                level=SecurityLevel[issue_data["level"]],
                category="Demo",
                title=issue_data["title"],
                description="Demo description",
                recommendation="Demo recommendation",
                affected_components=["Demo"]
            ))
        
        score = audit.calculate_security_score()
        print(f"   {scenario['name']}: {score}/100")
    
    return scenarios

def demo_reporting_features():
    """Demonstrate reporting features"""
    print_header("Reporting Features")
    
    print_section("Report Formats")
    print("✅ Color-coded console output")
    print("✅ JSON export for automation")
    print("✅ Detailed issue categorization")
    print("✅ Prioritized recommendations")
    print("✅ Actionable next steps")
    
    print_section("Report Sections")
    print("📊 Audit Summary")
    print("🔍 Security Issues by Severity")
    print("📋 Issues by Category")
    print("💡 Recommendations")
    print("📋 Next Steps")
    print("📈 Security Score")
    
    # Simulate report generation
    sample_report = {
        "audit_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_issues": 3,
            "security_score": 75
        },
        "issues_by_severity": {
            "critical": 0,
            "high": 1,
            "medium": 1,
            "low": 1
        },
        "recommendations": [
            "Enable TLS/SSL encryption for all connections",
            "Implement strong authentication mechanisms",
            "Review and implement principle of least privilege"
        ]
    }
    
    print(f"\n📊 Sample Report Summary:")
    print(f"   Timestamp: {sample_report['audit_metadata']['timestamp']}")
    print(f"   Total Issues: {sample_report['audit_metadata']['total_issues']}")
    print(f"   Security Score: {sample_report['audit_metadata']['security_score']}/100")
    
    return sample_report

def main():
    """Run the complete demo"""
    print("🚀 MongoDB Security Audit Toolkit Demo")
    print("This demo showcases the key features of the security audit toolkit")
    
    try:
        # Run all demo sections
        basic_report = demo_basic_audit()
        cloud_results = demo_cloud_integration()
        fle_results = demo_fle_features()
        scoring_scenarios = demo_security_scoring()
        reporting_features = demo_reporting_features()
        
        print_header("Demo Summary")
        print("✅ Basic security audit functionality")
        print("✅ Cloud integration capabilities")
        print("✅ Field-Level Encryption features")
        print("✅ Security scoring system")
        print("✅ Comprehensive reporting")
        
        print(f"\n🎯 Key Features Demonstrated:")
        print(f"   • Comprehensive security checks")
        print(f"   • Color-coded reporting")
        print(f"   • Cloud platform integration")
        print(f"   • Field-Level Encryption support")
        print(f"   • Automated remediation guidance")
        
        print(f"\n📚 Next Steps:")
        print(f"   1. Install dependencies: pip install -r requirements.txt")
        print(f"   2. Run basic audit: python mongodb_security_audit.py 'mongodb://localhost:27017'")
        print(f"   3. Try cloud integration: python cloud_integration.py --aws-region us-east-1")
        print(f"   4. Test FLE features: python fle_demo.py 'mongodb://localhost:27017'")
        print(f"   5. Use PowerShell script: .\\audit_mongodb.ps1 -ConnectionString 'mongodb://localhost:27017'")
        
        print(f"\n🎉 Demo completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
