#!/usr/bin/env python3
"""
Cloud Integration Module for MongoDB Security Audit Tool
Supports AWS DocumentDB and GCP MongoDB Atlas integration
"""

import boto3
import json
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError
import requests
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AWSIntegration:
    """AWS DocumentDB integration for MongoDB security auditing"""
    
    def __init__(self, region: str = 'us-east-1'):
        self.region = region
        self.docdb_client = None
        self.ec2_client = None
        self.iam_client = None
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize AWS clients"""
        try:
            self.docdb_client = boto3.client('docdb', region_name=self.region)
            self.ec2_client = boto3.client('ec2', region_name=self.region)
            self.iam_client = boto3.client('iam', region_name=self.region)
        except NoCredentialsError:
            logger.error("AWS credentials not found. Please configure AWS credentials.")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            raise
    
    def list_documentdb_clusters(self) -> List[Dict[str, Any]]:
        """List all DocumentDB clusters in the region"""
        try:
            response = self.docdb_client.describe_db_clusters()
            clusters = []
            
            for cluster in response.get('DBClusters', []):
                cluster_info = {
                    'cluster_identifier': cluster.get('DBClusterIdentifier'),
                    'engine': cluster.get('Engine'),
                    'status': cluster.get('Status'),
                    'endpoint': cluster.get('Endpoint'),
                    'port': cluster.get('Port'),
                    'vpc_security_groups': cluster.get('VpcSecurityGroups', []),
                    'backup_retention_period': cluster.get('BackupRetentionPeriod'),
                    'encryption_enabled': cluster.get('StorageEncrypted', False),
                    'deletion_protection': cluster.get('DeletionProtection', False),
                    'publicly_accessible': self._check_public_access(cluster)
                }
                clusters.append(cluster_info)
            
            return clusters
        except ClientError as e:
            logger.error(f"Error listing DocumentDB clusters: {e}")
            return []
    
    def _check_public_access(self, cluster: Dict[str, Any]) -> bool:
        """Check if cluster is publicly accessible"""
        try:
            # Get security groups
            security_group_ids = [sg['VpcSecurityGroupId'] for sg in cluster.get('VpcSecurityGroups', [])]
            
            for sg_id in security_group_ids:
                response = self.ec2_client.describe_security_groups(GroupIds=[sg_id])
                for sg in response.get('SecurityGroups', []):
                    for rule in sg.get('IpPermissions', []):
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                return True
            return False
        except Exception as e:
            logger.warning(f"Could not check public access for cluster {cluster.get('DBClusterIdentifier')}: {e}")
            return False
    
    def audit_documentdb_cluster(self, cluster_identifier: str) -> Dict[str, Any]:
        """Audit a specific DocumentDB cluster for security issues"""
        try:
            response = self.docdb_client.describe_db_clusters(
                DBClusterIdentifier=cluster_identifier
            )
            
            if not response.get('DBClusters'):
                return {'error': 'Cluster not found'}
            
            cluster = response['DBClusters'][0]
            issues = []
            
            # Check encryption at rest
            if not cluster.get('StorageEncrypted', False):
                issues.append({
                    'level': 'CRITICAL',
                    'category': 'Encryption',
                    'title': 'Encryption at Rest Not Enabled',
                    'description': 'DocumentDB cluster is not encrypted at rest',
                    'recommendation': 'Enable encryption at rest for the cluster'
                })
            
            # Check public accessibility
            if self._check_public_access(cluster):
                issues.append({
                    'level': 'CRITICAL',
                    'category': 'Network Security',
                    'title': 'Publicly Accessible Cluster',
                    'description': 'DocumentDB cluster is publicly accessible',
                    'recommendation': 'Restrict access to specific IP ranges or VPC'
                })
            
            # Check backup retention
            backup_retention = cluster.get('BackupRetentionPeriod', 0)
            if backup_retention < 7:
                issues.append({
                    'level': 'MEDIUM',
                    'category': 'Backup',
                    'title': 'Insufficient Backup Retention',
                    'description': f'Backup retention period is {backup_retention} days',
                    'recommendation': 'Increase backup retention to at least 7 days'
                })
            
            # Check deletion protection
            if not cluster.get('DeletionProtection', False):
                issues.append({
                    'level': 'MEDIUM',
                    'category': 'Data Protection',
                    'title': 'Deletion Protection Not Enabled',
                    'description': 'Cluster deletion protection is not enabled',
                    'recommendation': 'Enable deletion protection to prevent accidental deletion'
                })
            
            return {
                'cluster_identifier': cluster_identifier,
                'issues': issues,
                'audit_timestamp': datetime.now().isoformat(),
                'total_issues': len(issues)
            }
            
        except ClientError as e:
            logger.error(f"Error auditing DocumentDB cluster {cluster_identifier}: {e}")
            return {'error': str(e)}

class GCPIntegration:
    """GCP MongoDB Atlas integration for MongoDB security auditing"""
    
    def __init__(self, api_key: str, project_id: str):
        self.api_key = api_key
        self.project_id = project_id
        self.base_url = "https://cloud.mongodb.com/api/atlas/v1.0"
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    
    def list_atlas_clusters(self) -> List[Dict[str, Any]]:
        """List all MongoDB Atlas clusters"""
        try:
            url = f"{self.base_url}/groups/{self.project_id}/clusters"
            params = {'apiKey': self.api_key}
            
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            clusters = []
            for cluster in response.json().get('results', []):
                cluster_info = {
                    'name': cluster.get('name'),
                    'type': cluster.get('type'),
                    'state': cluster.get('stateName'),
                    'connection_string': cluster.get('connectionStrings', {}).get('standard'),
                    'encryption_at_rest': cluster.get('encryptionAtRestProvider'),
                    'backup_enabled': cluster.get('backupEnabled', False),
                    'disk_size_gb': cluster.get('diskSizeGB'),
                    'num_shards': cluster.get('numShards', 1)
                }
                clusters.append(cluster_info)
            
            return clusters
        except requests.RequestException as e:
            logger.error(f"Error listing Atlas clusters: {e}")
            return []
    
    def audit_atlas_cluster(self, cluster_name: str) -> Dict[str, Any]:
        """Audit a specific MongoDB Atlas cluster for security issues"""
        try:
            # Get cluster details
            url = f"{self.base_url}/groups/{self.project_id}/clusters/{cluster_name}"
            params = {'apiKey': self.api_key}
            
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            cluster = response.json()
            issues = []
            
            # Check encryption at rest
            if not cluster.get('encryptionAtRestProvider'):
                issues.append({
                    'level': 'CRITICAL',
                    'category': 'Encryption',
                    'title': 'Encryption at Rest Not Enabled',
                    'description': 'MongoDB Atlas cluster is not encrypted at rest',
                    'recommendation': 'Enable encryption at rest for the cluster'
                })
            
            # Check backup configuration
            if not cluster.get('backupEnabled', False):
                issues.append({
                    'level': 'HIGH',
                    'category': 'Backup',
                    'title': 'Backup Not Enabled',
                    'description': 'MongoDB Atlas cluster backup is not enabled',
                    'recommendation': 'Enable backup for the cluster'
                })
            
            # Check cluster type for production
            cluster_type = cluster.get('type', '')
            if cluster_type in ['M0', 'M2', 'M5']:
                issues.append({
                    'level': 'MEDIUM',
                    'category': 'Performance',
                    'title': 'Development Cluster in Production',
                    'description': f'Cluster is using {cluster_type} tier which is for development',
                    'recommendation': 'Use M10 or higher tier for production workloads'
                })
            
            return {
                'cluster_name': cluster_name,
                'issues': issues,
                'audit_timestamp': datetime.now().isoformat(),
                'total_issues': len(issues)
            }
            
        except requests.RequestException as e:
            logger.error(f"Error auditing Atlas cluster {cluster_name}: {e}")
            return {'error': str(e)}

class CloudAuditManager:
    """Manager class for cloud-based MongoDB auditing"""
    
    def __init__(self, aws_region: str = 'us-east-1', gcp_api_key: str = None, gcp_project_id: str = None):
        self.aws_integration = None
        self.gcp_integration = None
        
        try:
            self.aws_integration = AWSIntegration(aws_region)
        except Exception as e:
            logger.warning(f"AWS integration not available: {e}")
        
        if gcp_api_key and gcp_project_id:
            try:
                self.gcp_integration = GCPIntegration(gcp_api_key, gcp_project_id)
            except Exception as e:
                logger.warning(f"GCP integration not available: {e}")
    
    def audit_all_aws_clusters(self) -> List[Dict[str, Any]]:
        """Audit all AWS DocumentDB clusters"""
        if not self.aws_integration:
            return []
        
        clusters = self.aws_integration.list_documentdb_clusters()
        audit_results = []
        
        for cluster in clusters:
            cluster_id = cluster['cluster_identifier']
            audit_result = self.aws_integration.audit_documentdb_cluster(cluster_id)
            audit_results.append(audit_result)
        
        return audit_results
    
    def audit_all_gcp_clusters(self) -> List[Dict[str, Any]]:
        """Audit all GCP MongoDB Atlas clusters"""
        if not self.gcp_integration:
            return []
        
        clusters = self.gcp_integration.list_atlas_clusters()
        audit_results = []
        
        for cluster in clusters:
            cluster_name = cluster['name']
            audit_result = self.gcp_integration.audit_atlas_cluster(cluster_name)
            audit_results.append(audit_result)
        
        return audit_results
    
    def generate_cloud_report(self) -> Dict[str, Any]:
        """Generate comprehensive cloud audit report"""
        report = {
            'audit_metadata': {
                'timestamp': datetime.now().isoformat(),
                'aws_available': self.aws_integration is not None,
                'gcp_available': self.gcp_integration is not None
            },
            'aws_audit_results': [],
            'gcp_audit_results': [],
            'summary': {
                'total_aws_clusters': 0,
                'total_gcp_clusters': 0,
                'total_issues': 0
            }
        }
        
        # Audit AWS clusters
        if self.aws_integration:
            aws_results = self.audit_all_aws_clusters()
            report['aws_audit_results'] = aws_results
            report['summary']['total_aws_clusters'] = len(aws_results)
            report['summary']['total_issues'] += sum(len(result.get('issues', [])) for result in aws_results)
        
        # Audit GCP clusters
        if self.gcp_integration:
            gcp_results = self.audit_all_gcp_clusters()
            report['gcp_audit_results'] = gcp_results
            report['summary']['total_gcp_clusters'] = len(gcp_results)
            report['summary']['total_issues'] += sum(len(result.get('issues', [])) for result in gcp_results)
        
        return report

def main():
    """Example usage of cloud integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Cloud MongoDB Security Audit")
    parser.add_argument("--aws-region", default="us-east-1", help="AWS region")
    parser.add_argument("--gcp-api-key", help="GCP API key")
    parser.add_argument("--gcp-project-id", help="GCP project ID")
    parser.add_argument("--output", help="Output file for JSON report")
    
    args = parser.parse_args()
    
    # Initialize cloud audit manager
    manager = CloudAuditManager(
        aws_region=args.aws_region,
        gcp_api_key=args.gcp_api_key,
        gcp_project_id=args.gcp_project_id
    )
    
    # Generate cloud audit report
    report = manager.generate_cloud_report()
    
    # Print summary
    print(f"Cloud Audit Summary:")
    print(f"AWS Clusters: {report['summary']['total_aws_clusters']}")
    print(f"GCP Clusters: {report['summary']['total_gcp_clusters']}")
    print(f"Total Issues: {report['summary']['total_issues']}")
    
    # Save report if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Report saved to {args.output}")

if __name__ == "__main__":
    main()
