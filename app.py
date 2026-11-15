from datetime import datetime
from flask import Flask, render_template, request, jsonify
from scanner_engine import analyze_target

app = Flask(__name__)
SCAN_HISTORY = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/history')
def history():
    return render_template('history.html', history=SCAN_HISTORY)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    raw_url = data.get('url', '').strip()

    if not raw_url:
        return jsonify({'error': 'Введите адрес сайта'}), 400

    result = analyze_target(raw_url)

    vt_malicious = result['vt']['malicious'] if result.get('vt') else 0
    is_danger = bool(result.get('error')) or vt_malicious > 0 or len(result.get('threats', [])) > 0

    SCAN_HISTORY.insert(0, {
        'time': datetime.now().strftime('%H:%M:%S'),
        'domain': result.get('domain', raw_url),
        'ip': result.get('ip', '—'),
        'vt_text': f"{vt_malicious}/{result['vt']['total']}" if result.get('vt') else 'Нет данных',
        'status': 'Обнаружены риски' if is_danger else 'Безопасно',
        'is_danger': is_danger
    })
    del SCAN_HISTORY[20:]

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
