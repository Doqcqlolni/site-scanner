import os
import re
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

SUSPICIOUS_PATTERNS = [
    (r'coinhive|cryptonight|minero\.cc', 'Обнаружен потенциальный скрипт криптомайнера'),
    (r'<iframe[^>]+(display:\s*none|visibility:\s*hidden|width=["\']?0)', 'Обнаружен скрытый iframe (возможный редирект или загрузка вирусов)'),
    (r'eval\(base64_decode|eval\(atob\(|document\.write\(unescape\(', 'Обнаружен обфусцированный (скрытый) JavaScript-код'),
    (r'window\.location\s*=\s*["\']http', 'Обнаружен принудительный JS-редирект'),
    (r'href=["\'][^"\']+\.(exe|scr|bat|msi|vbs)["\']', 'На странице есть прямые ссылки на исполняемые файлы (.exe/.bat/.msi)')
]

BROWSER_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
    'Referer': 'https://www.google.com/'
}

def check_virustotal(domain):
    api_key = os.environ.get('VT_API_KEY')
    if not api_key:
        return None
    try:
        vt_resp = requests.get(
            f'https://www.virustotal.com/api/v3/domains/{domain}',
            headers={'x-apikey': api_key},
            timeout=6
        )
        if vt_resp.status_code == 200:
            stats = vt_resp.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
            total = sum(stats.values())
            return {'malicious': malicious, 'total': total}
    except Exception:
        pass
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    raw_url = data.get('url', '').strip()

    if not raw_url:
        return jsonify({'error': 'Введите адрес сайта'}), 400

    if not raw_url.startswith(('http://', 'https://')):
        target_url = 'https://' + raw_url
    else:
        target_url = raw_url

    domain = target_url.replace('https://', '').replace('http://', '').split('/')[0]
    vt_data = check_virustotal(domain)

    try:
        resp = requests.get(target_url, timeout=10, headers=BROWSER_HEADERS)
        html = resp.text
        headers = resp.headers

        is_https = resp.url.startswith('https://')

        sec_headers = []
        if 'Strict-Transport-Security' in headers:
            sec_headers.append('HSTS')
        if 'X-Frame-Options' in headers:
            sec_headers.append('X-Frame-Options')
        if 'Content-Security-Policy' in headers:
            sec_headers.append('CSP')

        threats = []
        if resp.status_code in (403, 503) or 'cf-mitigated' in headers:
            threats.append(f'Сайт заблокировал доступ сканеру (HTTP {resp.status_code}) — прямая проверка кода невозможна')
        else:
            for pattern, description in SUSPICIOUS_PATTERNS:
                if re.search(pattern, html, re.IGNORECASE):
                    threats.append(description)

        return jsonify({
            'domain': domain,
            'status_code': resp.status_code,
            'is_https': is_https,
            'sec_headers': sec_headers,
            'threats': threats,
            'vt': vt_data
        })

    except requests.exceptions.SSLError:
        return jsonify({'error': f'Ошибка SSL-сертификата у {domain}! Соединение небезопасно.', 'vt': vt_data}), 200
    except requests.exceptions.RequestException:
        return jsonify({'error': f'Не удалось подключиться к {domain}. Проверьте правильность адреса.', 'vt': vt_data}), 200

if __name__ == '__main__':
    app.run(debug=True)
