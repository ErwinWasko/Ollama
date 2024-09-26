document.addEventListener("DOMContentLoaded", function() {
    const resultsContainer = document.getElementById('results-container');
    const generateButton = document.getElementById('generate-btn');
    const stopButton = document.getElementById('stop-btn');
    const loadingIndicator = document.getElementById('loading');
    const toggleDarkMode = document.getElementById('toggle-dark-mode');
    const cvssFilter = document.getElementById('cvss');
    let allReports = []; // Przechowuje wszystkie raporty
    window.allReports = allReports;
    let currentCvssFilter = 'all'; // Aktualny filtr CVSS
    let fetchingComplete = false; // Flaga do zatrzymania pobierania po zakończeniu
    let headerUpdated = false; // Flaga, aby wywołać updateHeader tylko raz

    let darkMode = false;

    toggleDarkMode.addEventListener('click', () => {
        darkMode = !darkMode;
        document.body.classList.toggle('dark-mode');
        toggleDarkMode.classList.toggle('dark');
    });

    function updateHeader(totalReports, maxCvss) {
        const headerInfo = document.getElementById('header-info');
        headerInfo.innerHTML = `Found ${totalReports} Vulnerabilities (Max CVSS: ${maxCvss})`;
    }

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

    // Funkcja do zatrzymania generowania raportów
    function stopGenerating() {
        fetchingComplete = true;  // Ustawienie flagi, aby zatrzymać pobieranie
        loadingIndicator.style.display = 'none';  // Ukryj wskaźnik ładowania
        console.log('Report generation stopped');
    }

    generateButton.addEventListener('click', fetchData);
    stopButton.addEventListener('click', stopGenerating);

    function applyFilter(cvssFilterValue) {
        resultsContainer.innerHTML = '';  // Wyczyść poprzednie wyniki
        const filteredReports = allReports.filter(report => {
            const cvssScore = parseFloat(report.cvss) || 0;
            switch (cvssFilterValue) {
                case 'low': return cvssScore >= 0.1 && cvssScore <= 3.9;
                case 'medium': return cvssScore >= 4.0 && cvssScore <= 6.9;
                case 'high': return cvssScore >= 7.0 && cvssScore <= 8.9;
                case 'critical': return cvssScore >= 9.0 && cvssScore <= 10.0;
                default: return true;
            }
        });

        // Jeśli po zastosowaniu filtra nie znaleziono raportów
        if (filteredReports.length === 0) {
            resultsContainer.innerHTML = `
                <p class="no-reports-message">
                    <span class="warning-icon">⚠️</span> Nie znaleziono CVE dla tego filtra.
                </p>`;
        } else {
            // Wyświetlenie przefiltrowanych raportów
            filteredReports.forEach(displayReport);
        }
    }

    function fetchData() {
        if (fetchingComplete) return; // Zatrzymaj pobieranie, jeśli przetwarzanie jest zakończone

        loadingIndicator.style.display = 'block'; // Pokaż wskaźnik ładowania

        fetch(`/fetch_reports?cvss=${currentCvssFilter}`)
            .then(response => response.json())
            .then(data => {
                if (data.done || fetchingComplete) {
                    fetchingComplete = true; // Zakończ przetwarzanie, jeśli wszystko zostało przetworzone
                    loadingIndicator.style.display = 'none'; // Ukryj wskaźnik ładowania
                    checkNoReportsMessage(); // Sprawdź, czy wyświetlić komunikat o braku raportów
                } else {
                    allReports.push(data.result); // Dodaj raport do allReports
                    applyFilter(currentCvssFilter); // Tylko wyświetl raporty zgodne z aktualnym filtrem CVSS
                    
                    // Zaktualizuj header tylko raz, przy pierwszym wczytaniu danych
                    if (!headerUpdated) {
                        updateHeader(data.total_reports, data.max_cvss);
                        headerUpdated = true; // Ustaw flagę, aby nie aktualizować nagłówka ponownie
                    }

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
});
