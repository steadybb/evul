#!/usr/bin/env python3
# logger.py - Advanced logging with colours, emojis, and debug levels
# Features:
# - Colour-coded console output (supports Windows, macOS, Linux)
# - Emoji indicators for different log levels
# - File logging with rotation
# - Performance timing decorators
# - Request/response logging for debugging
# - Session tracking

import os
import sys
import time
import json
import logging
import functools
from datetime import datetime
from typing import Any, Callable, Optional, Dict, List
from pathlib import Path

# ==================== COLOUR CODES ====================
class Colours:
    """ANSI colour codes for console output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Foreground colours
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright foreground colours
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colours
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

# ==================== EMOJI MAPPINGS ====================
EMOJIS = {
    'DEBUG': '🐛',
    'INFO': '📡',
    'SUCCESS': '✅',
    'WARNING': '⚠️',
    'ERROR': '❌',
    'CRITICAL': '💀',
    'TOKEN': '🔑',
    'COOKIE': '🍪',
    'PHISH': '🎣',
    'WORM': '🕷️',
    'EXFIL': '📤',
    'PROXY': '🌐',
    'AUTH': '🔐',
    'API': '🌍',
    'DB': '🗄️',
    'THREAD': '🧵',
    'JITTER': '⏱️',
    'RETRY': '🔄',
    'CAPTURE': '📸',
    'DEVICE_CODE': '📱',
    'POLLING': '⏳',
    'REFRESH': '♻️',
    'COOKIE_JAR': '🥫',
}

# ==================== COLOURED LOGGER CLASS ====================
class ColouredLogger(logging.Logger):
    """Custom logger with colour and emoji support."""
    
    LEVEL_COLOURS = {
        logging.DEBUG: Colours.BRIGHT_BLACK,
        logging.INFO: Colours.CYAN,
        logging.WARNING: Colours.YELLOW,
        logging.ERROR: Colours.RED,
        logging.CRITICAL: Colours.BRIGHT_RED + Colours.BG_WHITE,
    }
    
    LEVEL_EMOJIS = {
        logging.DEBUG: EMOJIS['DEBUG'],
        logging.INFO: EMOJIS['INFO'],
        logging.WARNING: EMOJIS['WARNING'],
        logging.ERROR: EMOJIS['ERROR'],
        logging.CRITICAL: EMOJIS['CRITICAL'],
    }
    
    def __init__(self, name: str, level: int = logging.NOTSET):
        super().__init__(name, level)
        
    def _format_message(self, level: int, msg: str, extra_emoji: str = None) -> str:
        """Format message with colour and emoji."""
        colour = self.LEVEL_COLOURS.get(level, Colours.WHITE)
        emoji = extra_emoji or self.LEVEL_EMOJIS.get(level, '📋')
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        return f"{colour}{emoji} {timestamp} [{self.name}] {msg}{Colours.RESET}"
    
    def success(self, msg: str, *args, **kwargs):
        """Log a success message (green)."""
        colour = Colours.BRIGHT_GREEN
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['SUCCESS']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.INFO, msg, args, **kwargs)
    
    def token(self, msg: str, *args, **kwargs):
        """Log token-related messages with key emoji."""
        colour = Colours.BRIGHT_YELLOW
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['TOKEN']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.INFO, msg, args, **kwargs)
    
    def cookie(self, msg: str, *args, **kwargs):
        """Log cookie-related messages."""
        colour = Colours.BRIGHT_MAGENTA
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['COOKIE']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.INFO, msg, args, **kwargs)
    
    def phish(self, msg: str, *args, **kwargs):
        """Log phishing-related messages."""
        colour = Colours.BRIGHT_CYAN
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['PHISH']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.INFO, msg, args, **kwargs)
    
    def worm(self, msg: str, *args, **kwargs):
        """Log worm propagation messages."""
        colour = Colours.BRIGHT_GREEN
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['WORM']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.INFO, msg, args, **kwargs)
    
    def exfil(self, msg: str, *args, **kwargs):
        """Log exfiltration messages."""
        colour = Colours.BRIGHT_BLUE
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['EXFIL']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.INFO, msg, args, **kwargs)
    
    def proxy(self, msg: str, *args, **kwargs):
        """Log proxy-related messages."""
        colour = Colours.BRIGHT_BLACK
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['PROXY']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.DEBUG, msg, args, **kwargs)
    
    def api(self, msg: str, *args, **kwargs):
        """Log API request/response messages."""
        colour = Colours.BRIGHT_WHITE
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['API']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.DEBUG, msg, args, **kwargs)
    
    def db(self, msg: str, *args, **kwargs):
        """Log database-related messages."""
        colour = Colours.BRIGHT_BLACK
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['DB']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.INFO, msg, args, **kwargs)
    
    def thread(self, msg: str, *args, **kwargs):
        """Log thread-related messages."""
        colour = Colours.BRIGHT_CYAN
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['THREAD']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.DEBUG, msg, args, **kwargs)
    
    def capture(self, msg: str, *args, **kwargs):
        """Log capture-related messages."""
        colour = Colours.BRIGHT_GREEN
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['CAPTURE']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.INFO, msg, args, **kwargs)
    
    def device_code(self, msg: str, *args, **kwargs):
        """Log device code messages."""
        colour = Colours.BRIGHT_YELLOW
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['DEVICE_CODE']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.INFO, msg, args, **kwargs)
    
    def polling(self, msg: str, *args, **kwargs):
        """Log polling-related messages."""
        colour = Colours.CYAN
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['POLLING']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.INFO, msg, args, **kwargs)
    
    def refresh(self, msg: str, *args, **kwargs):
        """Log token refresh messages."""
        colour = Colours.BRIGHT_MAGENTA
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['REFRESH']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.INFO, msg, args, **kwargs)
    
    def jitter(self, msg: str, *args, **kwargs):
        """Log jitter/delay messages."""
        colour = Colours.DIM
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['JITTER']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.DEBUG, msg, args, **kwargs)
    
    def retry(self, msg: str, *args, **kwargs):
        """Log retry-related messages."""
        colour = Colours.BRIGHT_YELLOW
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        msg = f"{colour}{EMOJIS['RETRY']} {timestamp} [{self.name}] {msg}{Colours.RESET}"
        self._log(logging.WARNING, msg, args, **kwargs)

# ==================== FILE LOGGER (with rotation) ====================
class RotatingFileHandler(logging.Handler):
    """Simple file handler with rotation based on size."""
    
    def __init__(self, filename: str, max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5):
        super().__init__()
        self.filename = filename
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self._open_file()
    
    def _open_file(self):
        """Open the log file."""
        Path(os.path.dirname(self.filename)).mkdir(parents=True, exist_ok=True)
        self.stream = open(self.filename, 'a', encoding='utf-8')
    
    def _rotate(self):
        """Rotate the log file if it exceeds max size."""
        self.stream.close()
        
        # Rotate existing backups
        for i in range(self.backup_count - 1, 0, -1):
            src = f"{self.filename}.{i}"
            dst = f"{self.filename}.{i+1}"
            if os.path.exists(src):
                os.rename(src, dst)
        
        # Rename current log
        if os.path.exists(self.filename):
            os.rename(self.filename, f"{self.filename}.1")
        
        # Create new log file
        self._open_file()
    
    def emit(self, record: logging.LogRecord):
        """Write log record to file."""
        try:
            msg = self.format(record)
            self.stream.write(msg + '\n')
            self.stream.flush()
            
            # Check if rotation is needed
            if self.stream.tell() >= self.max_bytes:
                self._rotate()
        except Exception:
            self.handleError(record)

# ==================== JSON LOGGER (for structured logging) ====================
class JSONFormatter(logging.Formatter):
    """Format log records as JSON for machine parsing."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry)

# ==================== PERFORMANCE TIMING DECORATOR ====================
def log_time(logger_instance=None, level='debug'):
    """
    Decorator to log function execution time.
    
    Usage:
        @log_time()
        def my_function():
            pass
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000
            log = logger_instance or get_logger(func.__module__)
            log_func = getattr(log, level, log.debug)
            log_func(f"⏱️ {func.__name__} took {elapsed:.2f}ms")
            return result
        return wrapper
    return decorator

# ==================== REQUEST/LOGGING DECORATOR ====================
def log_request(logger_instance=None):
    """Decorator to log HTTP requests and responses."""
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            log = logger_instance or get_logger(func.__module__)
            
            # Log request details if available
            if args and hasattr(args[0], '__dict__'):
                log.api(f"Calling {func.__name__} with args={args[1:]} kwargs={kwargs}")
            
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                elapsed = (time.perf_counter() - start) * 1000
                log.api(f"✅ {func.__name__} completed in {elapsed:.2f}ms")
                return result
            except Exception as e:
                elapsed = (time.perf_counter() - start) * 1000
                log.error(f"❌ {func.__name__} failed after {elapsed:.2f}ms: {e}")
                raise
        return wrapper
    return decorator

# ==================== LOGGER MANAGER ====================
class LoggerManager:
    """Central manager for all loggers in the application."""
    
    _instance = None
    _loggers: Dict[str, ColouredLogger] = {}
    _console_handler: logging.Handler = None
    _file_handler: logging.Handler = None
    _json_handler: logging.Handler = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._setup()
        return cls._instance
    
    def _setup(self):
        """Setup the logging system."""
        # Register our custom logger class
        logging.setLoggerClass(ColouredLogger)
        
        # Get root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG if os.environ.get('DEBUG', '').lower() == 'true' else logging.INFO)
        
        # Console handler (coloured)
        self._console_handler = logging.StreamHandler(sys.stdout)
        self._console_handler.setLevel(logging.DEBUG)
        self._console_handler.setFormatter(logging.Formatter('%(message)s'))
        root_logger.addHandler(self._console_handler)
        
        # File handler (plain text with rotation)
        log_file = os.environ.get('LOG_FILE', 'logs/harvester.log')
        if log_file:
            try:
                self._file_handler = RotatingFileHandler(log_file)
                self._file_handler.setLevel(logging.DEBUG)
                self._file_handler.setFormatter(logging.Formatter(
                    '%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                ))
                root_logger.addHandler(self._file_handler)
            except Exception as e:
                print(f"Failed to create file logger: {e}")
        
        # JSON handler (for structured logging)
        json_log_file = os.environ.get('JSON_LOG_FILE', '')
        if json_log_file:
            try:
                self._json_handler = RotatingFileHandler(json_log_file)
                self._json_handler.setLevel(logging.DEBUG)
                self._json_handler.setFormatter(JSONFormatter())
                root_logger.addHandler(self._json_handler)
            except Exception as e:
                print(f"Failed to create JSON logger: {e}")
    
    def get_logger(self, name: str) -> ColouredLogger:
        """Get or create a logger instance."""
        if name not in self._loggers:
            self._loggers[name] = logging.getLogger(name)
        return self._loggers[name]
    
    def set_level(self, level: int):
        """Set logging level for all handlers."""
        self._console_handler.setLevel(level)
        if self._file_handler:
            self._file_handler.setLevel(level)
        if self._json_handler:
            self._json_handler.setLevel(level)
    
    def shutdown(self):
        """Cleanup logging handlers."""
        logging.shutdown()

# ==================== CONVENIENCE FUNCTIONS ====================
_manager = None

def get_logger(name: str = 'root') -> ColouredLogger:
    """Get a logger instance by name."""
    global _manager
    if _manager is None:
        _manager = LoggerManager()
    return _manager.get_logger(name)

def set_log_level(level: str):
    """Set log level from string."""
    level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL,
    }
    if _manager:
        _manager.set_level(level_map.get(level.upper(), logging.INFO))

# ==================== SESSION LOGGER (for tracking individual capture sessions) ====================
class SessionLogger:
    """Logger for tracking individual capture sessions."""
    
    def __init__(self, session_id: str, log_dir: str = 'logs/sessions'):
        self.session_id = session_id
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / f"{session_id}.log"
        self.events = []
    
    def log_event(self, event_type: str, data: Any):
        """Log an event for this session."""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'data': data
        }
        self.events.append(event)
        
        # Write to session log file
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
    
    def get_events(self) -> List[Dict]:
        """Get all events for this session."""
        return self.events
    
    def summary(self) -> Dict:
        """Generate a summary of the session."""
        if not self.events:
            return {}
        
        start_time = self.events[0]['timestamp']
        end_time = self.events[-1]['timestamp']
        
        return {
            'session_id': self.session_id,
            'start_time': start_time,
            'end_time': end_time,
            'total_events': len(self.events),
            'event_types': list(set(e['type'] for e in self.events)),
        }

# ==================== BANNER FUNCTION ====================
def print_banner():
    """Print a cool ASCII banner at startup."""
    banner = f"""
{Colours.BRIGHT_RED}╔═══════════════════════════════════════════════════════════════════╗
║                                                                           ║
║  {Colours.BRIGHT_GREEN}██████╗ ███████╗██╗   ██╗██╗ ██████╗███████╗{Colours.BRIGHT_RED}                   ║
║  {Colours.BRIGHT_GREEN}██╔══██╗██╔════╝██║   ██║██║██╔════╝██╔════╝{Colours.BRIGHT_RED}                   ║
║  {Colours.BRIGHT_GREEN}██║  ██║█████╗  ██║   ██║██║██║     █████╗  {Colours.BRIGHT_RED}                   ║
║  {Colours.BRIGHT_GREEN}██║  ██║██╔══╝  ╚██╗ ██╔╝██║██║     ██╔══╝  {Colours.BRIGHT_RED}                   ║
║  {Colours.BRIGHT_GREEN}██████╔╝███████╗ ╚████╔╝ ██║╚██████╗███████╗{Colours.BRIGHT_RED}                   ║
║  {Colours.BRIGHT_GREEN}╚═════╝ ╚══════╝  ╚═══╝  ╚═╝ ╚═════╝╚══════╝{Colours.BRIGHT_RED}                   ║
║                                                                           ║
║  {Colours.BRIGHT_YELLOW}Device Code Token Harvester{Colours.RESET}{Colours.BRIGHT_RED}                                  ║
║  {Colours.BRIGHT_CYAN}Red Team Tool - Authorized Testing Only{Colours.RESET}{Colours.BRIGHT_RED}                    ║
║                                                                           ║
║  {Colours.BRIGHT_WHITE}Features:{Colours.RESET}{Colours.BRIGHT_RED}                                                      ║
║    • Async SSE Polling                      • Proxy Rotation              ║
║    • Smart Jitter                           • Playwright Support          ║
║    • Worm Propagation                       • Smart Targeting             ║
║    • Multiple Exfil Channels                • AES-256 Encryption          ║
║    • Conditional Access Detection           • Session Persistence         ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colours.RESET}
"""
    print(banner)

# ==================== INITIALIZATION ====================
# Create default log directory
Path('logs').mkdir(exist_ok=True)

# Export main functions
__all__ = [
    'get_logger',
    'set_log_level',
    'SessionLogger',
    'log_time',
    'log_request',
    'print_banner',
    'Colours',
    'EMOJIS',
]

# ==================== EXAMPLE USAGE ====================
if __name__ == '__main__':
    # Test the logger
    print_banner()
    
    logger = get_logger('test')
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.success("This is a success message!")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.token("Access token obtained")
    logger.cookie("Session cookie harvested")
    logger.phish("Phishing email sent to victim@example.com")
    logger.worm("Propagating to 3 new targets")
    logger.exfil("Exfiltrating payload via HTTP")
    logger.proxy("Using proxy http://proxy:8080")
    logger.api("GET /api/device-code 200 OK")
    logger.db("Database initialized at: worm_state.db")
    logger.thread("Started polling thread for session abc123")
    logger.capture("Token capture completed successfully")
    logger.device_code("Device code: ABCD1234")
    logger.polling("Polling for token (interval: 5s)")
    logger.refresh("Token refreshed successfully")
    logger.jitter("Applied jitter delay: 2.3s")
    logger.retry("Retry attempt 2/3")
    
    # Test session logger
    session_logger = SessionLogger("test-session-123")
    session_logger.log_event("device_code_requested", {"user_code": "ABCD1234"})
    session_logger.log_event("token_obtained", {"scope": "User.Read"})
    print(f"\nSession summary: {session_logger.summary()}")
