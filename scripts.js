
    document.addEventListener("DOMContentLoaded", function() {
    const resultsContainer = document.getElementById('results-container');
    const loadingIndicator = document.getElementById('loading');
    const toggleDarkMode = document.getElementById('toggle-dark-mode');
    const cvssFilter = document.getElementById('cvss');
    const printPdfButton = document.getElementById('print-pdf');
    const printWordButton = document.getElementById('print-word');
    let allReports = []; // Przechowuje wszystkie raporty
    let currentCvssFilter = 'all'; // Aktualny filtr CVSS
    let fetchingComplete = false; // Flaga do zatrzymania pobierania po zakończeniu

    let darkMode = false;

    toggleDarkMode.addEventListener('click', () => {
        darkMode = !darkMode;
        document.body.classList.toggle('dark-mode');
        toggleDarkMode.classList.toggle('dark');
    });

    function formatOllamaResponse(responseText) {
        return responseText.replace(/\*\*(.*?)\*\*/g, '<br><strong>$1</strong><br>');
    }

    function displayReport(report) {
        const card = document.createElement('div');
        card.classList.add('card');

        const formattedAnalysis = formatOllamaResponse(report.ollama_analysis || 'No analysis available');

        card.innerHTML = `
            <h3><a href="${report.cve_link}" target="_blank">${report.cve}</a></h3>
            <p><strong>CVSS Score:</strong> ${report.cvss || 'N/A'}</p>
            <p><strong>Description:</strong> ${report.description || 'No description available'}</p>
            <div class="ollama-analysis">
                <strong>Ollama Analysis:</strong>
                <p>${formattedAnalysis}</p>
            </div>
        `;

        resultsContainer.appendChild(card);

        setTimeout(() => {
            card.classList.add('show');
        }, 100);
    }

    function applyFilter(cvssFilterValue) {
                resultsContainer.innerHTML = '';
                allReports.filter(report => {
                    const cvssScore = parseFloat(report.cvss) || 0;
                    switch (cvssFilterValue) {
                        case 'low': return cvssScore >= 0.1 && cvssScore <= 3.9;
                        case 'medium': return cvssScore >= 4.0 && cvssScore <= 6.9;
                        case 'high': return cvssScore >= 7.0 && cvssScore <= 8.9;
                        case 'critical': return cvssScore >= 9.0 && cvssScore <= 10.0;
                        default: return true;
                    }
                }).forEach(displayReport);
            }

            cvssFilter.addEventListener('change', function() {
                currentCvssFilter = cvssFilter.value;
                applyFilter(currentCvssFilter);
            });

    function fetchData() {
        if (fetchingComplete) return; // Zatrzymaj pobieranie, jeśli przetwarzanie jest zakończone

        loadingIndicator.style.display = 'block'; // Pokaż wskaźnik ładowania

        fetch(`/fetch_reports?cvss=${currentCvssFilter}`)
            .then(response => response.json())
            .then(data => {
                if (data.done) {
                    fetchingComplete = true; // Zakończ przetwarzanie, jeśli wszystko zostało przetworzone
                    loadingIndicator.style.display = 'none'; // Ukryj wskaźnik ładowania
                    checkNoReportsMessage(); // Sprawdź, czy wyświetlić komunikat o braku raportów
                } else {
                    allReports.push(data); // Dodaj raport do allReports
                    applyFilter(currentCvssFilter); // Tylko wyświetl raporty zgodne z aktualnym filtrem CVSS
                    setTimeout(fetchData, 500); // Kontynuuj pobieranie danych
                }
            })
            .catch(error => {
                console.error('Error fetching data:', error);
                loadingIndicator.style.display = 'none'; // Ukryj wskaźnik ładowania w przypadku błędu
            });
    }

    function checkNoReportsMessage() {
        if (resultsContainer.children.length === 0) {
            resultsContainer.innerHTML = '<p class="no-reports-message">No reports found for the selected CVSS score.</p>';
        }
    }

    cvssFilter.addEventListener('change', function() {
        currentCvssFilter = cvssFilter.value; // Zaktualizuj aktualny filtr CVSS
        applyFilter(currentCvssFilter); // Zastosuj filtr na podstawie wartości CVSS
    });

    function collectReports() {
        return allReports.map(report => ({
            cve: report.cve,
            cvss: report.cvss,
            description: report.description,
            ollama_analysis: report.ollama_analysis
        }));
    }

    // Obsługa przycisku Print to PDF
    printPdfButton.addEventListener("click", function() {
        const reports = collectReports();  // Zbierz wszystkie raporty
        if (reports.length === 0) return;

        fetch('/generate_pdf_report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ reports })  // Przekaż wszystkie raporty
        })
        .then(response => response.blob())
        .then(blob => {
            const link = document.createElement('a');
            link.href = window.URL.createObjectURL(blob);
            link.download = "Raporty_CVSS.pdf";
            link.click();
        })
        .catch(error => console.error('Error generating PDF:', error));
    });

    // Obsługa przycisku Print to Word
    printWordButton.addEventListener("click", function() {
        const reports = collectReports();  // Zbierz wszystkie raporty
        if (reports.length === 0) return;

        fetch('/generate_word_report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ reports })  // Przekaż wszystkie raporty
        })
        .then(response => response.blob())
        .then(blob => {
            const link = document.createElement('a');
            link.href = window.URL.createObjectURL(blob);
            link.download = "Raporty_CVSS.docx";
            link.click();
        })
        .catch(error => console.error('Error generating Word:', error));
    });


    fetchData(); // Rozpocznij pobieranie danych
});

        
