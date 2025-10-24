#!/usr/bin/env python3
"""
Test script for MongoDB Security Audit Toolkit
Validates all components and functionality
"""

import unittest
import json
import tempfile
import os
import sys
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mongodb_security_audit import MongoDBSecurityAudit, SecurityLevel, SecurityIssue
from cloud_integration import AWSIntegration, GCPIntegration, CloudAuditManager
from fle_demo import FLEManager, FLESecurityAudit

class TestMongoDBSecurityAudit(unittest.TestCase):
    """Test cases for MongoDB Security Audit"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.audit = MongoDBSecurityAudit("mongodb://localhost:27017")
    
    def test_security_issue_creation(self):
        """Test SecurityIssue creation"""
        issue = SecurityIssue(
            level=SecurityLevel.CRITICAL,
            category="Test",
            title="Test Issue",
            description="Test description",
            recommendation="Test recommendation",
            affected_components=["Component1"]
        )
        
        self.assertEqual(issue.level, SecurityLevel.CRITICAL)
        self.assertEqual(issue.category, "Test")
        self.assertEqual(issue.title, "Test Issue")
    
    def test_security_score_calculation(self):
        """Test security score calculation"""
        # Add some test issues
        self.audit.issues = [
            SecurityIssue(SecurityLevel.CRITICAL, "Test", "Test1", "Desc1", "Rec1", ["Comp1"]),
            SecurityIssue(SecurityLevel.HIGH, "Test", "Test2", "Desc2", "Rec2", ["Comp2"]),
            SecurityIssue(SecurityLevel.MEDIUM, "Test", "Test3", "Desc3", "Rec3", ["Comp3"])
        ]
        
        score = self.audit.calculate_security_score()
        expected_score = 100 - 25 - 15 - 10  # 50
        self.assertEqual(score, expected_score)
    
    def test_report_generation(self):
        """Test report generation"""
        # Add a test issue
        self.audit.issues = [
            SecurityIssue(SecurityLevel.HIGH, "Test", "Test Issue", "Description", "Recommendation", ["Component"])
        ]
        
        report = self.audit.generate_report()
        
        self.assertIn("audit_metadata", report)
        self.assertIn("issues_by_severity", report)
        self.assertIn("recommendations", report)
        self.assertEqual(report["audit_metadata"]["total_issues"], 1)
        self.assertEqual(len(report["issues_by_severity"]["high"]), 1)

class TestCloudIntegration(unittest.TestCase):
    """Test cases for Cloud Integration"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.aws_region = "us-east-1"
        self.gcp_api_key = "test-api-key"
        self.gcp_project_id = "test-project"
    
    @patch('boto3.client')
    def test_aws_integration_initialization(self, mock_boto3):
        """Test AWS integration initialization"""
        mock_client = Mock()
        mock_boto3.return_value = mock_client
        
        aws_integration = AWSIntegration(self.aws_region)
        self.assertIsNotNone(aws_integration.docdb_client)
        self.assertIsNotNone(aws_integration.ec2_client)
        self.assertIsNotNone(aws_integration.iam_client)
    
    def test_gcp_integration_initialization(self):
        """Test GCP integration initialization"""
        gcp_integration = GCPIntegration(self.gcp_api_key, self.gcp_project_id)
        self.assertEqual(gcp_integration.api_key, self.gcp_api_key)
        self.assertEqual(gcp_integration.project_id, self.gcp_project_id)
    
    def test_cloud_audit_manager_initialization(self):
        """Test Cloud Audit Manager initialization"""
        manager = CloudAuditManager(
            aws_region=self.aws_region,
            gcp_api_key=self.gcp_api_key,
            gcp_project_id=self.gcp_project_id
        )
        self.assertIsNotNone(manager)

class TestFLEManager(unittest.TestCase):
    """Test cases for Field-Level Encryption Manager"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.fle_manager = FLEManager("mongodb://localhost:27017")
    
    def test_master_key_generation(self):
        """Test master key generation"""
        master_key = self.fle_manager.generate_master_key()
        self.assertIsInstance(master_key, bytes)
        self.assertEqual(len(master_key), 32)  # 256 bits
    
    def test_fle_security_audit_initialization(self):
        """Test FLE Security Audit initialization"""
        fle_audit = FLESecurityAudit("mongodb://localhost:27017")
        self.assertIsNotNone(fle_audit.fle_manager)

class TestReportGeneration(unittest.TestCase):
    """Test cases for report generation"""
    
    def test_json_report_serialization(self):
        """Test JSON report serialization"""
        audit = MongoDBSecurityAudit("mongodb://localhost:27017")
        audit.issues = [
            SecurityIssue(SecurityLevel.HIGH, "Test", "Test Issue", "Description", "Recommendation", ["Component"])
        ]
        
        report = audit.generate_report()
        
        # Test JSON serialization
        json_str = json.dumps(report, default=str)
        self.assertIsInstance(json_str, str)
        
        # Test JSON deserialization
        parsed_report = json.loads(json_str)
        self.assertEqual(parsed_report["audit_metadata"]["total_issues"], 1)

class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_end_to_end_audit_simulation(self):
        """Test end-to-end audit simulation"""
        # Mock MongoDB connection
        with patch('pymongo.MongoClient') as mock_client:
            mock_instance = Mock()
            mock_client.return_value = mock_instance
            mock_instance.admin.command.return_value = {"authenticationMechanisms": ["SCRAM-SHA-256"]}
            
            audit = MongoDBSecurityAudit("mongodb://localhost:27017")
            
            # Test connection
            with patch.object(audit, 'connect', return_value=True):
                # Test audit execution
                with patch.object(audit, 'check_authentication'):
                    report = audit.generate_report()
                    self.assertIsNotNone(report)
                    self.assertIn("audit_metadata", report)

class TestConfiguration(unittest.TestCase):
    """Test cases for configuration handling"""
    
    def test_config_file_loading(self):
        """Test configuration file loading"""
        config_data = {
            "mongodb": {
                "connection_timeout": 5000
            },
            "security": {
                "score_threshold": 80
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name
        
        try:
            with open(config_file, 'r') as f:
                loaded_config = json.load(f)
            
            self.assertEqual(loaded_config["mongodb"]["connection_timeout"], 5000)
            self.assertEqual(loaded_config["security"]["score_threshold"], 80)
        finally:
            os.unlink(config_file)

def run_tests():
    """Run all test cases"""
    print("Running MongoDB Security Audit Toolkit Tests...")
    print("=" * 50)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestMongoDBSecurityAudit,
        TestCloudIntegration,
        TestFLEManager,
        TestReportGeneration,
        TestIntegration,
        TestConfiguration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    print(f"\nOverall result: {'PASSED' if success else 'FAILED'}")
    
    return success

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
