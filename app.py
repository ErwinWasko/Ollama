from flask import Flask, render_template, jsonify, request
import skaner
import time

app = Flask(__name__)

# Przechowuje bieżące raporty, które są analizowane
current_reports = []
all_reports_fetched = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/fetch_reports')
def fetch_reports():
    global current_reports, all_reports_fetched

    if all_reports_fetched and not current_reports:
        return jsonify({})  # Zwraca pustą odpowiedź, jeśli wszystkie raporty zostały już przetworzone

    if not current_reports:
        current_reports = skaner.fetch_security_reports()

    selected_cvss = request.args.get('cvss', 'all')

    while current_reports:
        report = current_reports.pop(0)
        cve = report.get('vulnerability')
        cvss = float(report.get('vulnerability_score', 0))
        description = report.get('vulnerability_description', 'No description available')
        
        if selected_cvss != 'all':
            if selected_cvss == 'low' and not (0.1 <= cvss <= 3.9):
                continue
            if selected_cvss == 'medium' and not (4.0 <= cvss <= 6.9):
                continue
            if selected_cvss == 'high' and not (7.0 <= cvss <= 8.9):
                continue
            if selected_cvss == 'critical' and not (9.0 <= cvss <= 10.0):
                continue

        mitre_data = skaner.fetch_mitre_data(cve)
        description, ref_urls = skaner.process_mitre_data(mitre_data)
        
        ollama_analysis = skaner.analyze_data_with_ollama(cve, cvss, description, ref_urls)
        
        result = {
            'cve': cve,
            'cvss': cvss,
            'description': description,
            'ollama_analysis': ollama_analysis,
            'cve_link': f'https://www.cve.org/CVERecord?id={cve}'
        }
        
        if not current_reports:  # Sprawdzenie, czy wszystkie raporty zostały przetworzone
            all_reports_fetched = True
        
        time.sleep(2)  # Symulowanie przetwarzania danych
        
        return jsonify(result)
    
    return jsonify({})

if __name__ == '__main__':
    app.run(debug=True)
