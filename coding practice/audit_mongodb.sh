#!/bin/bash

# MongoDB Security Audit Script
# Easy-to-use wrapper for the MongoDB Security Audit Toolkit

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
CONNECTION_STRING=""
USERNAME=""
PASSWORD=""
OUTPUT_FILE=""
AUDIT_TYPE="basic"
AWS_REGION="us-east-1"
GCP_API_KEY=""
GCP_PROJECT_ID=""

# Function to display usage
usage() {
    echo "MongoDB Security Audit Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -c, --connection-string STRING  MongoDB connection string (required for basic audit)"
    echo "  -u, --username USERNAME         MongoDB username"
    echo "  -p, --password PASSWORD         MongoDB password"
    echo "  -o, --output FILE               Output file for JSON report"
    echo "  -t, --type TYPE                 Audit type: basic, cloud, fle (default: basic)"
    echo "  --aws-region REGION            AWS region for cloud audit (default: us-east-1)"
    echo "  --gcp-api-key KEY              GCP API key for Atlas audit"
    echo "  --gcp-project-id ID            GCP project ID for Atlas audit"
    echo "  -h, --help                     Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -c 'mongodb://localhost:27017'"
    echo "  $0 -c 'mongodb://user:pass@host:27017/db' -o report.json"
    echo "  $0 -t cloud --aws-region us-west-2 -o aws_audit.json"
    echo "  $0 -t fle -c 'mongodb://localhost:27017' -o fle_audit.json"
}

# Function to check if Python is available
check_python() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}Error: Python 3 is required but not installed.${NC}"
        exit 1
    fi
}

# Function to check if required packages are installed
check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    if ! python3 -c "import pymongo, colorama" 2>/dev/null; then
        echo -e "${YELLOW}Installing required packages...${NC}"
        pip3 install -r requirements.txt
    fi
    
    echo -e "${GREEN}Dependencies OK${NC}"
}

# Function to run basic audit
run_basic_audit() {
    echo -e "${BLUE}Running basic MongoDB security audit...${NC}"
    
    if [ -z "$CONNECTION_STRING" ]; then
        echo -e "${RED}Error: Connection string is required for basic audit${NC}"
        exit 1
    fi
    
    local cmd="python3 mongodb_security_audit.py \"$CONNECTION_STRING\""
    
    if [ -n "$USERNAME" ]; then
        cmd="$cmd -u \"$USERNAME\""
    fi
    
    if [ -n "$PASSWORD" ]; then
        cmd="$cmd -p \"$PASSWORD\""
    fi
    
    if [ -n "$OUTPUT_FILE" ]; then
        cmd="$cmd -o \"$OUTPUT_FILE\""
    fi
    
    eval $cmd
}

# Function to run cloud audit
run_cloud_audit() {
    echo -e "${BLUE}Running cloud MongoDB security audit...${NC}"
    
    local cmd="python3 cloud_integration.py"
    
    if [ -n "$AWS_REGION" ]; then
        cmd="$cmd --aws-region \"$AWS_REGION\""
    fi
    
    if [ -n "$GCP_API_KEY" ]; then
        cmd="$cmd --gcp-api-key \"$GCP_API_KEY\""
    fi
    
    if [ -n "$GCP_PROJECT_ID" ]; then
        cmd="$cmd --gcp-project-id \"$GCP_PROJECT_ID\""
    fi
    
    if [ -n "$OUTPUT_FILE" ]; then
        cmd="$cmd --output \"$OUTPUT_FILE\""
    fi
    
    eval $cmd
}

# Function to run FLE audit
run_fle_audit() {
    echo -e "${BLUE}Running Field-Level Encryption audit...${NC}"
    
    if [ -z "$CONNECTION_STRING" ]; then
        echo -e "${RED}Error: Connection string is required for FLE audit${NC}"
        exit 1
    fi
    
    local cmd="python3 fle_demo.py \"$CONNECTION_STRING\" --audit-only"
    
    if [ -n "$OUTPUT_FILE" ]; then
        cmd="$cmd --output \"$OUTPUT_FILE\""
    fi
    
    eval $cmd
}

# Function to run FLE demonstration
run_fle_demo() {
    echo -e "${BLUE}Running Field-Level Encryption demonstration...${NC}"
    
    if [ -z "$CONNECTION_STRING" ]; then
        echo -e "${RED}Error: Connection string is required for FLE demo${NC}"
        exit 1
    fi
    
    python3 fle_demo.py "$CONNECTION_STRING"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--connection-string)
            CONNECTION_STRING="$2"
            shift 2
            ;;
        -u|--username)
            USERNAME="$2"
            shift 2
            ;;
        -p|--password)
            PASSWORD="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -t|--type)
            AUDIT_TYPE="$2"
            shift 2
            ;;
        --aws-region)
            AWS_REGION="$2"
            shift 2
            ;;
        --gcp-api-key)
            GCP_API_KEY="$2"
            shift 2
            ;;
        --gcp-project-id)
            GCP_PROJECT_ID="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    echo -e "${GREEN}MongoDB Security Audit Toolkit${NC}"
    echo -e "${GREEN}============================${NC}"
    
    check_python
    check_dependencies
    
    case $AUDIT_TYPE in
        basic)
            run_basic_audit
            ;;
        cloud)
            run_cloud_audit
            ;;
        fle)
            run_fle_audit
            ;;
        fle-demo)
            run_fle_demo
            ;;
        *)
            echo -e "${RED}Error: Invalid audit type: $AUDIT_TYPE${NC}"
            echo "Valid types: basic, cloud, fle, fle-demo"
            exit 1
            ;;
    esac
    
    if [ -n "$OUTPUT_FILE" ]; then
        echo -e "${GREEN}Report saved to: $OUTPUT_FILE${NC}"
    fi
    
    echo -e "${GREEN}Audit completed successfully!${NC}"
}

# Run main function
main "$@"
