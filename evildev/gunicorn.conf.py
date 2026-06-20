# evildev/gunicorn.conf.py
bind = "0.0.0.0:10000"
workers = 2
timeout = 900           # 15 minutes - matches device code expiration
worker_class = "sync"
keepalive = 2
graceful_timeout = 30
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
accesslog = "-"
errorlog = "-"
loglevel = "info"
