#!/usr/bin/env python3
"""
MongoDB Field-Level Encryption (FLE) Demonstration
Shows how to implement and use FLE for sensitive data protection
"""

import os
import json
import base64
from typing import Dict, Any, List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pymongo
from pymongo import MongoClient
from pymongo.encryption import ClientEncryption, Algorithm
from pymongo.encryption_options import AutoEncryptionOpts
import bson
from bson import ObjectId
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FLEManager:
    """MongoDB Field-Level Encryption Manager"""
    
    def __init__(self, connection_string: str, key_vault_namespace: str = "encryption.__keyVault"):
        self.connection_string = connection_string
        self.key_vault_namespace = key_vault_namespace
        self.client = None
        self.client_encryption = None
        self.encrypted_client = None
        self.master_key = None
        self.data_key_id = None
        
    def generate_master_key(self) -> bytes:
        """Generate a master key for encryption"""
        # In production, use a proper key management system
        password = b"my-secret-password"
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.master_key = kdf.derive(password)
        return self.master_key
    
    def connect(self) -> bool:
        """Establish connection to MongoDB"""
        try:
            self.client = MongoClient(self.connection_string)
            self.client.admin.command('ping')
            return True
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            return False
    
    def setup_encryption(self) -> bool:
        """Set up field-level encryption"""
        try:
            if not self.client:
                return False
            
            # Generate master key
            self.generate_master_key()
            
            # Create client encryption
            self.client_encryption = ClientEncryption(
                self.client,
                {
                    "local": {
                        "key": self.master_key
                    }
                },
                "encryption.__keyVault"
            )
            
            # Create data key
            self.data_key_id = self.client_encryption.create_data_key("local")
            
            # Set up encrypted client
            schema_map = {
                "test.encrypted_collection": {
                    "bsonType": "object",
                    "encryptMetadata": {
                        "keyId": [self.data_key_id]
                    },
                    "properties": {
                        "ssn": {
                            "encrypt": {
                                "bsonType": "string",
                                "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                            }
                        },
                        "credit_card": {
                            "encrypt": {
                                "bsonType": "string",
                                "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                            }
                        },
                        "name": {
                            "bsonType": "string"
                        }
                    }
                }
            }
            
            auto_encryption_opts = AutoEncryptionOpts(
                {"local": {"key": self.master_key}},
                "encryption.__keyVault",
                schema_map=schema_map
            )
            
            self.encrypted_client = MongoClient(
                self.connection_string,
                auto_encryption_opts=auto_encryption_opts
            )
            
            return True
        except Exception as e:
            logger.error(f"Failed to setup encryption: {e}")
            return False
    
    def create_encrypted_collection(self) -> bool:
        """Create a collection with encrypted fields"""
        try:
            if not self.encrypted_client:
                return False
            
            db = self.encrypted_client.test
            collection = db.encrypted_collection
            
            # Insert encrypted document
            document = {
                "name": "John Doe",
                "ssn": "123-45-6789",  # This will be encrypted
                "credit_card": "4111-1111-1111-1111",  # This will be encrypted
                "email": "john.doe@example.com"
            }
            
            result = collection.insert_one(document)
            logger.info(f"Inserted encrypted document with ID: {result.inserted_id}")
            
            return True
        except Exception as e:
            logger.error(f"Failed to create encrypted collection: {e}")
            return False
    
    def demonstrate_encryption(self) -> Dict[str, Any]:
        """Demonstrate field-level encryption capabilities"""
        demo_results = {
            "encryption_setup": False,
            "data_insertion": False,
            "encrypted_data_visible": False,
            "decrypted_data_visible": False,
            "comparison_queries": False,
            "issues_found": []
        }
        
        try:
            # Setup encryption
            if not self.setup_encryption():
                demo_results["issues_found"].append("Failed to setup encryption")
                return demo_results
            
            demo_results["encryption_setup"] = True
            
            # Create encrypted collection
            if not self.create_encrypted_collection():
                demo_results["issues_found"].append("Failed to create encrypted collection")
                return demo_results
            
            demo_results["data_insertion"] = True
            
            # Check encrypted data visibility (should be encrypted)
            db = self.client.test
            collection = db.encrypted_collection
            
            raw_document = collection.find_one()
            if raw_document:
                demo_results["encrypted_data_visible"] = True
                logger.info("Raw encrypted document:")
                logger.info(f"  Name: {raw_document.get('name')}")
                logger.info(f"  SSN: {raw_document.get('ssn')} (encrypted)")
                logger.info(f"  Credit Card: {raw_document.get('credit_card')} (encrypted)")
            
            # Check decrypted data visibility (should be readable)
            encrypted_db = self.encrypted_client.test
            encrypted_collection = encrypted_db.encrypted_collection
            
            decrypted_document = encrypted_collection.find_one()
            if decrypted_document:
                demo_results["decrypted_data_visible"] = True
                logger.info("Decrypted document:")
                logger.info(f"  Name: {decrypted_document.get('name')}")
                logger.info(f"  SSN: {decrypted_document.get('ssn')} (decrypted)")
                logger.info(f"  Credit Card: {decrypted_document.get('credit_card')} (decrypted)")
            
            # Test comparison queries on encrypted fields
            try:
                # This should work with deterministic encryption
                ssn_query = encrypted_collection.find({"ssn": "123-45-6789"})
                if ssn_query.count() > 0:
                    demo_results["comparison_queries"] = True
                    logger.info("✅ Comparison query on encrypted SSN field successful")
            except Exception as e:
                logger.warning(f"Comparison query failed: {e}")
            
            return demo_results
            
        except Exception as e:
            logger.error(f"Encryption demonstration failed: {e}")
            demo_results["issues_found"].append(str(e))
            return demo_results
    
    def cleanup(self):
        """Clean up encryption setup"""
        try:
            if self.client:
                # Drop the test collection
                self.client.test.encrypted_collection.drop()
                # Drop the key vault collection
                self.client.encryption.__keyVault.drop()
                logger.info("Cleaned up encryption setup")
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")

class FLESecurityAudit:
    """Security audit specifically for Field-Level Encryption"""
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.fle_manager = FLEManager(connection_string)
        self.issues = []
    
    def check_fle_implementation(self) -> List[Dict[str, Any]]:
        """Check if FLE is properly implemented"""
        issues = []
        
        try:
            if not self.fle_manager.connect():
                issues.append({
                    "level": "CRITICAL",
                    "category": "FLE Implementation",
                    "title": "Cannot Connect to MongoDB",
                    "description": "Unable to establish connection to MongoDB for FLE audit",
                    "recommendation": "Verify MongoDB connection and credentials"
                })
                return issues
            
            # Check if encryption is enabled
            try:
                result = self.fle_manager.client.admin.command("getParameter", "enableEncryption")
                if not result.get("enableEncryption", False):
                    issues.append({
                        "level": "HIGH",
                        "category": "FLE Implementation",
                        "title": "FLE Not Enabled",
                        "description": "Field-Level Encryption is not enabled on the MongoDB instance",
                        "recommendation": "Enable FLE by setting enableEncryption=true in MongoDB configuration"
                    })
            except Exception:
                issues.append({
                    "level": "MEDIUM",
                    "category": "FLE Implementation",
                    "title": "FLE Status Unknown",
                    "description": "Could not determine FLE status",
                    "recommendation": "Manually verify FLE configuration"
                })
            
            # Check for key management
            try:
                key_vault = self.fle_manager.client.encryption.__keyVault
                key_count = key_vault.count_documents({})
                if key_count == 0:
                    issues.append({
                        "level": "HIGH",
                        "category": "FLE Key Management",
                        "title": "No Encryption Keys Found",
                        "description": "No encryption keys found in the key vault",
                        "recommendation": "Generate and store encryption keys for FLE"
                    })
            except Exception:
                issues.append({
                    "level": "MEDIUM",
                    "category": "FLE Key Management",
                    "title": "Key Vault Not Accessible",
                    "description": "Could not access the encryption key vault",
                    "recommendation": "Verify key vault permissions and configuration"
                })
            
            return issues
            
        except Exception as e:
            issues.append({
                "level": "CRITICAL",
                "category": "FLE Implementation",
                "title": "FLE Audit Failed",
                "description": f"FLE security audit failed: {e}",
                "recommendation": "Review MongoDB configuration and try again"
            })
            return issues
    
    def generate_fle_report(self) -> Dict[str, Any]:
        """Generate FLE-specific security report"""
        issues = self.check_fle_implementation()
        
        # Run FLE demonstration
        demo_results = self.fle_manager.demonstrate_encryption()
        
        report = {
            "fle_audit_metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "connection_string": self.connection_string,
                "total_issues": len(issues)
            },
            "fle_issues": issues,
            "fle_demonstration": demo_results,
            "fle_recommendations": self._generate_fle_recommendations(issues, demo_results)
        }
        
        return report
    
    def _generate_fle_recommendations(self, issues: List[Dict[str, Any]], demo_results: Dict[str, Any]) -> List[str]:
        """Generate FLE-specific recommendations"""
        recommendations = []
        
        if not demo_results.get("encryption_setup"):
            recommendations.append("🔐 Implement Field-Level Encryption for sensitive data")
        
        if not demo_results.get("comparison_queries"):
            recommendations.append("🔍 Use deterministic encryption for fields that need to be queryable")
        
        if any(issue["category"] == "FLE Key Management" for issue in issues):
            recommendations.append("🗝️ Implement proper key management for FLE")
        
        if not demo_results.get("data_insertion"):
            recommendations.append("📝 Test FLE implementation with sample data")
        
        recommendations.extend([
            "🛡️ Use random encryption for highly sensitive data that doesn't need to be queryable",
            "📊 Monitor FLE performance impact on your application",
            "🔄 Implement key rotation policies for FLE keys",
            "📋 Document FLE schema and encryption policies"
        ])
        
        return recommendations

def main():
    """Example usage of FLE demonstration"""
    import argparse
    
    parser = argparse.ArgumentParser(description="MongoDB Field-Level Encryption Demo")
    parser.add_argument("connection_string", help="MongoDB connection string")
    parser.add_argument("--audit-only", action="store_true", help="Only run FLE audit, don't demonstrate")
    parser.add_argument("--output", help="Output file for JSON report")
    
    args = parser.parse_args()
    
    # Initialize FLE manager
    fle_manager = FLEManager(args.connection_string)
    
    if args.audit_only:
        # Run FLE security audit
        audit = FLESecurityAudit(args.connection_string)
        report = audit.generate_fle_report()
        
        print("FLE Security Audit Report:")
        print(f"Total Issues: {report['fle_audit_metadata']['total_issues']}")
        
        for issue in report['fle_issues']:
            print(f"- {issue['level']}: {issue['title']}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2, default=str)
    else:
        # Run FLE demonstration
        print("Running FLE Demonstration...")
        demo_results = fle_manager.demonstrate_encryption()
        
        print("\nFLE Demonstration Results:")
        for key, value in demo_results.items():
            if key != "issues_found":
                status = "✅" if value else "❌"
                print(f"{status} {key}: {value}")
        
        if demo_results.get("issues_found"):
            print("\nIssues Found:")
            for issue in demo_results["issues_found"]:
                print(f"  - {issue}")
        
        # Cleanup
        fle_manager.cleanup()

if __name__ == "__main__":
    main()
