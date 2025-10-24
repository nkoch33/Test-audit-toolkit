# MongoDB Security Audit Script (PowerShell)
# Easy-to-use wrapper for the MongoDB Security Audit Toolkit

param(
    [Parameter(Mandatory=$false)]
    [string]$ConnectionString = "",
    
    [Parameter(Mandatory=$false)]
    [string]$Username = "",
    
    [Parameter(Mandatory=$false)]
    [string]$Password = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("basic", "cloud", "fle", "fle-demo")]
    [string]$AuditType = "basic",
    
    [Parameter(Mandatory=$false)]
    [string]$AwsRegion = "us-east-1",
    
    [Parameter(Mandatory=$false)]
    [string]$GcpApiKey = "",
    
    [Parameter(Mandatory=$false)]
    [string]$GcpProjectId = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Function to display usage
function Show-Usage {
    Write-Host "MongoDB Security Audit Script" -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage: .\audit_mongodb.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -ConnectionString STRING  MongoDB connection string (required for basic audit)"
    Write-Host "  -Username USERNAME        MongoDB username"
    Write-Host "  -Password PASSWORD        MongoDB password"
    Write-Host "  -OutputFile FILE          Output file for JSON report"
    Write-Host "  -AuditType TYPE           Audit type: basic, cloud, fle, fle-demo (default: basic)"
    Write-Host "  -AwsRegion REGION         AWS region for cloud audit (default: us-east-1)"
    Write-Host "  -GcpApiKey KEY            GCP API key for Atlas audit"
    Write-Host "  -GcpProjectId ID          GCP project ID for Atlas audit"
    Write-Host "  -Help                     Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\audit_mongodb.ps1 -ConnectionString 'mongodb://localhost:27017'"
    Write-Host "  .\audit_mongodb.ps1 -ConnectionString 'mongodb://user:pass@host:27017/db' -OutputFile 'report.json'"
    Write-Host "  .\audit_mongodb.ps1 -AuditType cloud -AwsRegion us-west-2 -OutputFile 'aws_audit.json'"
    Write-Host "  .\audit_mongodb.ps1 -AuditType fle -ConnectionString 'mongodb://localhost:27017' -OutputFile 'fle_audit.json'"
}

# Function to check if Python is available
function Test-Python {
    try {
        $pythonVersion = python --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Python not found"
        }
        Write-Host "Python found: $pythonVersion" -ForegroundColor Green
    }
    catch {
        Write-Host "Error: Python is required but not installed." -ForegroundColor Red
        exit 1
    }
}

# Function to check if required packages are installed
function Test-Dependencies {
    Write-Host "Checking dependencies..." -ForegroundColor Blue
    
    try {
        python -c "import pymongo, colorama" 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Dependencies not found"
        }
        Write-Host "Dependencies OK" -ForegroundColor Green
    }
    catch {
        Write-Host "Installing required packages..." -ForegroundColor Yellow
        pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to install dependencies" -ForegroundColor Red
            exit 1
        }
    }
}

# Function to run basic audit
function Start-BasicAudit {
    Write-Host "Running basic MongoDB security audit..." -ForegroundColor Blue
    
    if ([string]::IsNullOrEmpty($ConnectionString)) {
        Write-Host "Error: Connection string is required for basic audit" -ForegroundColor Red
        exit 1
    }
    
    $cmd = "python mongodb_security_audit.py `"$ConnectionString`""
    
    if (![string]::IsNullOrEmpty($Username)) {
        $cmd += " -u `"$Username`""
    }
    
    if (![string]::IsNullOrEmpty($Password)) {
        $cmd += " -p `"$Password`""
    }
    
    if (![string]::IsNullOrEmpty($OutputFile)) {
        $cmd += " -o `"$OutputFile`""
    }
    
    Invoke-Expression $cmd
}

# Function to run cloud audit
function Start-CloudAudit {
    Write-Host "Running cloud MongoDB security audit..." -ForegroundColor Blue
    
    $cmd = "python cloud_integration.py"
    
    if (![string]::IsNullOrEmpty($AwsRegion)) {
        $cmd += " --aws-region `"$AwsRegion`""
    }
    
    if (![string]::IsNullOrEmpty($GcpApiKey)) {
        $cmd += " --gcp-api-key `"$GcpApiKey`""
    }
    
    if (![string]::IsNullOrEmpty($GcpProjectId)) {
        $cmd += " --gcp-project-id `"$GcpProjectId`""
    }
    
    if (![string]::IsNullOrEmpty($OutputFile)) {
        $cmd += " --output `"$OutputFile`""
    }
    
    Invoke-Expression $cmd
}

# Function to run FLE audit
function Start-FleAudit {
    Write-Host "Running Field-Level Encryption audit..." -ForegroundColor Blue
    
    if ([string]::IsNullOrEmpty($ConnectionString)) {
        Write-Host "Error: Connection string is required for FLE audit" -ForegroundColor Red
        exit 1
    }
    
    $cmd = "python fle_demo.py `"$ConnectionString`" --audit-only"
    
    if (![string]::IsNullOrEmpty($OutputFile)) {
        $cmd += " --output `"$OutputFile`""
    }
    
    Invoke-Expression $cmd
}

# Function to run FLE demonstration
function Start-FleDemo {
    Write-Host "Running Field-Level Encryption demonstration..." -ForegroundColor Blue
    
    if ([string]::IsNullOrEmpty($ConnectionString)) {
        Write-Host "Error: Connection string is required for FLE demo" -ForegroundColor Red
        exit 1
    }
    
    python fle_demo.py $ConnectionString
}

# Main execution
function Main {
    if ($Help) {
        Show-Usage
        return
    }
    
    Write-Host "MongoDB Security Audit Toolkit" -ForegroundColor Green
    Write-Host "============================" -ForegroundColor Green
    
    Test-Python
    Test-Dependencies
    
    switch ($AuditType) {
        "basic" {
            Start-BasicAudit
        }
        "cloud" {
            Start-CloudAudit
        }
        "fle" {
            Start-FleAudit
        }
        "fle-demo" {
            Start-FleDemo
        }
        default {
            Write-Host "Error: Invalid audit type: $AuditType" -ForegroundColor Red
            Write-Host "Valid types: basic, cloud, fle, fle-demo"
            exit 1
        }
    }
    
    if (![string]::IsNullOrEmpty($OutputFile)) {
        Write-Host "Report saved to: $OutputFile" -ForegroundColor Green
    }
    
    Write-Host "Audit completed successfully!" -ForegroundColor Green
}

# Run main function
Main
