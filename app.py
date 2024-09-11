from flask import Flask, render_template
import skaner  # Importujemy skaner.py

app = Flask(__name__)

@app.route('/')
def index():
    # Uruchomienie funkcji głównej z skaner.py, aby pobrać wyniki analizy
    reports = skaner.fetch_security_reports()
    
    results = []
    for report in reports:
        cve = report.get('vulnerability')
        cvss = report.get('vulnerability_score', 'N/A')
        description = report.get('vulnerability_description', 'No description available')
        
        mitre_data = skaner.fetch_mitre_data(cve)
        description, ref_urls = skaner.process_mitre_data(mitre_data)
        
        ollama_analysis = skaner.analyze_data_with_ollama(cve, cvss, description, ref_urls)
        
        results.append({
            'cve': cve,
            'ollama_analysis': ollama_analysis
        })

    # Przekazanie wyników do szablonu HTML
    return render_template('index.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
