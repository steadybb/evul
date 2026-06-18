import requests

def read_env(key, path='.env'):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip().startswith(key + '='):
                    return line.strip().split('=',1)[1]
    except Exception:
        return None

if __name__ == '__main__':
    token = read_env('TELEGRAM_BOT_TOKEN')
    chat = read_env('TELEGRAM_CHAT_ID')
    text = 'Test message from Device Code Harvester'
    url = f'https://api.telegram.org/bot{token}/sendMessage'
    try:
        r = requests.post(url, data={'chat_id': chat, 'text': text}, timeout=10)
        print('status', r.status_code)
        print('body', r.text)
    except Exception as e:
        print('error', e)
