from flask import Flask, render_template, jsonify, request, send_file
import skaner
import time
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io
from docx import Document

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

    # Pobranie parametru cvss z żądania
    selected_cvss = request.args.get('cvss', 'all')

    # Inicjalizacja raportów, jeśli są puste i jeszcze nie pobraliśmy wszystkich
    if not current_reports and not all_reports_fetched:
        current_reports = skaner.fetch_security_reports()

    # Sprawdzenie, czy wszystkie raporty zostały przetworzone
    if all_reports_fetched or not current_reports:
        return jsonify({'done': True})  # Zwróć informację o zakończeniu

    # Przetwarzanie raportów jeden po drugim
    report = current_reports.pop(0)  # Pobieramy pierwszy raport z listy
    cve = report.get('vulnerability')
    cvss = float(report.get('vulnerability_score', 0))
    description = report.get('vulnerability_description', 'No description available')

    # Jeśli raport spełnia warunki, przetwarzamy go
    mitre_data = skaner.fetch_mitre_data(cve)
    description, ref_urls = skaner.process_mitre_data(mitre_data)

    # Pobieranie analizy Ollamy
    ollama_analysis = skaner.analyze_data_with_ollama(cve, cvss, description, ref_urls)

    result = {
        'cve': cve,
        'cvss': cvss,
        'description': description,
        'ollama_analysis': ollama_analysis,
        'cve_link': f'https://www.cve.org/CVERecord?id={cve}'
    }

    # Sprawdzenie, czy przetworzono już wszystkie raporty
    if not current_reports:
        all_reports_fetched = True

    return jsonify(result)

# Funkcja do generowania pliku PDF
@app.route('/generate_pdf_report', methods=['POST'])
def generate_pdf_report():
    data = request.json
    reports = data.get('reports', [])
    
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y_position = height - 50

    # Rysowanie każdego raportu
    for report in reports:
        c.drawString(100, y_position, f"CVE: {report['cve']}")
        c.drawString(100, y_position - 20, f"CVSS Score: {report['cvss']}")
        c.drawString(100, y_position - 40, f"Description: {report['description']}")
        c.drawString(100, y_position - 60, f"Ollama Analysis: {report['ollama_analysis']}")
        y_position -= 100  # Przesunięcie w dół dla kolejnego raportu
        if y_position < 100:
            c.showPage()
            y_position = height - 50

    c.save()

    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="Raporty_CVSS.pdf", mimetype='application/pdf')

# Funkcja do generowania pliku Word
@app.route('/generate_word_report', methods=['POST'])
def generate_word_report():
    data = request.json
    reports = data.get('reports', [])
    
    document = Document()
    document.add_heading('Raporty CVSS', 0)

    # Dodawanie każdego raportu do pliku Word
    for report in reports:
        document.add_heading(f'Report for {report["cve"]}', level=1)
        document.add_paragraph(f'CVSS Score: {report["cvss"]}')
        document.add_paragraph(f'Description: {report["description"]}')
        document.add_paragraph(f'Ollama Analysis: {report["ollama_analysis"]}')
        document.add_paragraph('')

    buffer = io.BytesIO()
    document.save(buffer)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="Raporty_CVSS.docx", mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')

if __name__ == '__main__':
    app.run(debug=True)
