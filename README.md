# MongoDB Security Audit Toolkit

A comprehensive Python toolkit for auditing MongoDB deployments (local or cloud-hosted) for common security misconfigurations and producing detailed, color-coded reports.

##  Features

### Core Security Checks
- **TLS/SSL Encryption**: Detects unencrypted connections
- **Authentication**: Identifies weak or missing authentication mechanisms
- **Network Security**: Checks for open network bindings and default ports
- **Access Control**: Audits user privileges and role assignments
- **Encryption at Rest**: Verifies data encryption in storage
- **Audit Logging**: Checks if audit logging is enabled
- **Replica Set Security**: Validates replica set configurations

### Cloud Integration
- **AWS DocumentDB**: Automated scanning of AWS DocumentDB clusters
- **GCP MongoDB Atlas**: Integration with Google Cloud MongoDB Atlas
- **Automated Discovery**: Automatically finds and audits cloud MongoDB instances

### Field-Level Encryption (FLE)
- **FLE Implementation**: Demonstrates MongoDB Field-Level Encryption
- **Encryption Testing**: Shows how to encrypt/decrypt sensitive data
- **Key Management**: Demonstrates proper key management practices
- **Query Capabilities**: Shows deterministic vs random encryption

##  Requirements

- Python 3.7+
- MongoDB 3.6+ (for FLE features)
- Required Python packages (see requirements.txt)

##  Installation

1. Clone or download the toolkit files
2. Install dependencies:
```bash
pip install -r requirements.txt
```

##  Usage

### Basic Security Audit

```bash
# Audit local MongoDB instance
python mongodb_security_audit.py "mongodb://localhost:27017"

# Audit with authentication
python mongodb_security_audit.py "mongodb://localhost:27017" -u username -p password

# Save report to file
python mongodb_security_audit.py "mongodb://localhost:27017" -o security_report.json

# Output only JSON (for automation)
python mongodb_security_audit.py "mongodb://localhost:27017" --json-only
```

### Cloud Integration

#### AWS DocumentDB
```bash
# Audit all AWS DocumentDB clusters
python cloud_integration.py --aws-region us-east-1 -o aws_audit.json
```

#### GCP MongoDB Atlas
```bash
# Audit MongoDB Atlas clusters
python cloud_integration.py --gcp-api-key YOUR_API_KEY --gcp-project-id YOUR_PROJECT_ID -o gcp_audit.json
```

### Field-Level Encryption Demo

```bash
# Run FLE demonstration
python fle_demo.py "mongodb://localhost:27017"

# Run FLE security audit only
python fle_demo.py "mongodb://localhost:27017" --audit-only -o fle_audit.json
```

##  Report Format

The toolkit generates comprehensive reports with:

### Security Score
- **80-100**: Excellent security posture
- **60-79**: Good security with some improvements needed
- **0-59**: Poor security posture requiring immediate attention

### Issue Classification
- ** CRITICAL**: Immediate action required
- ** HIGH**: Address within 48 hours
- ** MEDIUM**: Address within 1 week
- ** LOW**: Address when convenient
- ** INFO**: Informational only

### Categories
- **Encryption**: TLS/SSL, encryption at rest
- **Authentication**: User authentication mechanisms
- **Network Security**: Ports, bindings, access controls
- **Access Control**: User privileges, role assignments
- **Logging**: Audit logging configuration
- **Backup**: Backup and recovery settings

##  Security Checks Performed

### Network Security
- [ ] TLS/SSL encryption enabled
- [ ] Non-default ports in use
- [ ] Network binding restrictions
- [ ] Firewall configuration

### Authentication & Authorization
- [ ] Authentication mechanisms enabled
- [ ] Strong authentication methods (SCRAM-SHA-256)
- [ ] User privilege review
- [ ] Role-based access control

### Data Protection
- [ ] Encryption at rest
- [ ] Field-level encryption (FLE)
- [ ] Backup encryption
- [ ] Data classification

### Monitoring & Logging
- [ ] Audit logging enabled
- [ ] Security event monitoring
- [ ] Log retention policies
- [ ] Alert configuration

### Compliance
- [ ] GDPR compliance checks
- [ ] HIPAA compliance checks
- [ ] SOX compliance checks
- [ ] Industry best practices

##  Advanced Usage

### Custom Security Checks

You can extend the toolkit by adding custom security checks:

```python
from mongodb_security_audit import MongoDBSecurityAudit, SecurityIssue, SecurityLevel

class CustomAudit(MongoDBSecurityAudit):
    def check_custom_security(self):
        # Add your custom security check here
        if self.some_condition:
            self.issues.append(SecurityIssue(
                level=SecurityLevel.HIGH,
                category="Custom",
                title="Custom Security Issue",
                description="Description of the issue",
                recommendation="How to fix it",
                affected_components=["Component1", "Component2"]
            ))
```

### Integration with CI/CD

```bash
# Run audit in CI pipeline
python mongodb_security_audit.py "$MONGODB_URI" --json-only | jq '.audit_metadata.security_score'

# Fail pipeline if security score is below threshold
if [ $(python mongodb_security_audit.py "$MONGODB_URI" --json-only | jq '.audit_metadata.security_score') -lt 80 ]; then
    echo "Security score too low!"
    exit 1
fi
```

##  Configuration

### Environment Variables

```bash
# MongoDB connection
export MONGODB_URI="mongodb://username:password@host:port/database"

# AWS credentials
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# GCP credentials
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account.json"
```

### Configuration File

Create a `config.json` file for default settings:

```json
{
    "default_connection_timeout": 5000,
    "security_score_threshold": 80,
    "excluded_checks": [],
    "custom_checks": [],
    "report_format": "colored"
}
```

##  Best Practices

### Regular Auditing
- Run security audits weekly
- Integrate with CI/CD pipelines
- Monitor security score trends
- Document remediation actions

### Remediation Priority
1. **Critical Issues**: Fix immediately
2. **High Issues**: Fix within 48 hours
3. **Medium Issues**: Fix within 1 week
4. **Low Issues**: Fix within 1 month

### Continuous Improvement
- Update security checks regularly
- Monitor MongoDB security advisories
- Implement additional custom checks
- Review and update security policies

##  Troubleshooting

### Common Issues

**Connection Failed**
```
 Failed to connect to MongoDB: [Errno 111] Connection refused
```
- Check if MongoDB is running
- Verify connection string
- Check firewall settings

**Authentication Failed**
```
 Failed to connect to MongoDB: Authentication failed
```
- Verify username and password
- Check user permissions
- Ensure authentication is enabled

**Permission Denied**
```
 Operation not permitted
```
- Check user privileges
- Verify database access rights
- Review role assignments

### Debug Mode

Enable debug logging:

```bash
export PYTHONPATH=.
python -c "import logging; logging.basicConfig(level=logging.DEBUG)"
python mongodb_security_audit.py "mongodb://localhost:27017"
```

##  Contributing

1. Fork the repository
2. Create a feature branch
3. Add your security checks
4. Test thoroughly
5. Submit a pull request

##  License

This project is licensed under the MIT License - see the LICENSE file for details.

##  Disclaimer

This tool is for educational and security assessment purposes only. Always test in a non-production environment first. The authors are not responsible for any damage caused by the use of this tool.

##  Support

For issues and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review MongoDB security documentation

##  Resources

- [MongoDB Security Checklist](https://docs.mongodb.com/manual/security/)
- [MongoDB Field-Level Encryption](https://docs.mongodb.com/manual/core/security-encryption-at-rest/)
- [MongoDB Security Best Practices](https://docs.mongodb.com/manual/security-best-practices/)
- [OWASP Database Security](https://owasp.org/www-project-database-security/)
