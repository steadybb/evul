#!/usr/bin/env python3
import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path('evildev')))

# Load env
with open('.env.test') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            os.environ[key.strip()] = value.strip()

from evildev.worm import EmailTemplateLoader

loader = EmailTemplateLoader()
html, is_html = loader.load_template()
rendered = loader.render_template('John', 'ABC123', 'https://login.microsoft.com', email='john@example.com')

# Check for unresolved placeholders
unresolved = []
for word in ['name', 'user_code', 'verification_uri', 'date']:
    pattern1 = '{' + word + '}'
    pattern2 = '{{ ' + word + ' }}'
    if pattern1 in rendered or pattern2 in rendered:
        unresolved.append(word)

if unresolved:
    print(f'Unresolved placeholders: {unresolved}')
    sys.exit(1)
else:
    print('✓ All placeholders resolved!')
    print(f'Rendered size: {len(rendered)} bytes')
    print(f'Contains ABC123: {"ABC123" in rendered}')
    print(f'Contains John: {"John" in rendered}')
    sys.exit(0)
