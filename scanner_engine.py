import os
import re
import time
import socket
import requests

SUSPICIOUS_PATTERNS = [
    (r'coinhive|cryptonight|minero\.cc', 'Обнаружен потенциальный скрипт криптомайнера'),
    (r'<iframe[^>]+(display:\s*none|visibility:\s*hidden|width=["\']?0)', 'Обнаружен скрытый iframe (возможный редирект или загрузка вирусов)'),
    (r'eval\(base64_decode|eval\(atob\(|document\.write\(unescape\(', 'Обнаружен обфусцированный (скрытый) JavaScript-код'),
    (r'window\.location\s*=\s*["\']http', 'Обнаружен принудительный JS-редирект'),
    (r'href=["\'][^"\']+\.(exe|scr|bat|msi|vbs)["\']', 'На странице есть прямые ссылки на исполняемые файлы (.exe/.bat/.msi)')
]

SECURITY_HEADERS_LIST = [
    ('Strict-Transport-Security', 'HSTS (принудительный HTTPS)'),
    ('X-Frame-Options', 'Защита от Clickjacking (встраивания в iframe)'),
    ('Content-Security-Policy', 'CSP (защита от XSS-инъекций)'),
    ('X-Content-Type-Options', 'Защита от подмены MIME-типов'),
    ('Referrer-Policy', 'Контроль передачи источника перехода')
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
            attrs = vt_resp.json()['data']['attributes']
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
            total = sum(stats.values())

            flagged_vendors = []
            results = attrs.get('last_analysis_results', {})
            for vendor, info in results.items():
                if info.get('category') in ('malicious', 'suspicious'):
                    flagged_vendors.append(f"{vendor} ({info.get('result', 'Threat')})")

            return {
                'malicious': malicious,
                'total': total,
                'reputation': attrs.get('reputation', 0),
                'registrar': attrs.get('registrar', 'Не указан'),
                'flagged_vendors': flagged_vendors[:15]
            }
    except Exception:
        pass
    return None

def analyze_target(raw_url):
    target_url = raw_url if raw_url.startswith(('http://', 'https://')) else 'https://' + raw_url
    domain = target_url.replace('https://', '').replace('http://', '').split('/')[0]

    try:
        ip_address = socket.gethostbyname(domain)
    except Exception:
        ip_address = 'Не удалось определить'

    vt_data = check_virustotal(domain)

    try:
        start_time = time.time()
        resp = requests.get(target_url, timeout=10, headers=BROWSER_HEADERS)
        response_ms = round((time.time() - start_time) * 1000)

        html = resp.text
        headers = resp.headers
        is_https = resp.url.startswith('https://')
        server_software = headers.get('Server', 'Скрыто сервером')

        headers_audit = []
        present_short = []
        for header_key, header_desc in SECURITY_HEADERS_LIST:
            is_present = header_key in headers
            if is_present:
                present_short.append(header_key)
            headers_audit.append({
                'name': header_key,
                'desc': header_desc,
                'present': is_present
            })

        is_blocked = resp.status_code in (403, 503) or 'cf-mitigated' in headers
        threats = []
        page_stats = {
            'accessible': not is_blocked,
            'title': 'Недоступно (блокировка)',
            'scripts_count': 0,
            'forms_count': 0,
            'iframes_count': 0
        }

        if is_blocked:
            threats.append(f'Сайт заблокировал доступ сканеру (HTTP {resp.status_code}) — прямая проверка кода невозможна')
        else:
            for pattern, description in SUSPICIOUS_PATTERNS:
                if re.search(pattern, html, re.IGNORECASE):
                    threats.append(description)

            title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            page_stats['title'] = title_match.group(1).strip()[:80] if title_match else 'Без заголовка'
            page_stats['scripts_count'] = len(re.findall(r'<script\b', html, re.IGNORECASE))
            page_stats['forms_count'] = len(re.findall(r'<form\b', html, re.IGNORECASE))
            page_stats['iframes_count'] = len(re.findall(r'<iframe\b', html, re.IGNORECASE))

        return {
            'domain': domain,
            'ip': ip_address,
            'final_url': resp.url,
            'server': server_software,
            'response_ms': response_ms,
            'status_code': resp.status_code,
            'is_https': is_https,
            'sec_headers': present_short,
            'headers_audit': headers_audit,
            'threats': threats,
            'page_stats': page_stats,
            'vt': vt_data
        }

    except requests.exceptions.SSLError:
        return {'error': f'Ошибка SSL-сертификата у {domain}! Соединение небезопасно.', 'domain': domain, 'ip': ip_address, 'vt': vt_data}
    except requests.exceptions.RequestException:
        return {'error': f'Не удалось подключиться к {domain}. Проверьте правильность адреса.', 'domain': domain, 'ip': ip_address, 'vt': vt_data}
