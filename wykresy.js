document.addEventListener("DOMContentLoaded", function() {
    const showChartButton = document.getElementById("show-chart");

    showChartButton.addEventListener("click", function() {
        // Tworzenie modala lub otwieranie nowej strony z wykresem
        const chartModal = document.createElement('div');
        chartModal.style.position = 'fixed';
        chartModal.style.top = '50%';
        chartModal.style.left = '50%';
        chartModal.style.transform = 'translate(-50%, -50%)';
        chartModal.style.width = '80%';
        chartModal.style.height = '80%';
        chartModal.style.backgroundColor = '#fff';
        chartModal.style.border = '1px solid #ddd';
        chartModal.style.padding = '20px';
        chartModal.style.zIndex = 1000;
        chartModal.style.overflow = 'auto';
        chartModal.id = "chart-modal";

        const closeModal = document.createElement('button');
        closeModal.textContent = 'Zamknij';
        closeModal.style.marginBottom = '20px';
        closeModal.onclick = function() {
            document.body.removeChild(chartModal);
        };

        const chartCanvas = document.createElement('canvas');
        chartCanvas.id = 'vulnerabilityChart';
        chartModal.appendChild(closeModal);
        chartModal.appendChild(chartCanvas);

        document.body.appendChild(chartModal);

        // Pobieranie danych z serwera
        fetch('/fetch_chart_data')
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Brak danych do wyświetlenia wykresu.');
                    return;
                }

                const cvssData = data.cvss_ranges;
                
                const labels = Object.keys(cvssData);
                const values = Object.values(cvssData);

                // Tworzenie wykresu Chart.js
                const ctx = document.getElementById('vulnerabilityChart').getContext('2d');

                const chartData = {
                    labels: labels,
                    datasets: [{
                        label: 'Low (0.1-3.9)',
                        data: values,
                        backgroundColor: [
                        'rgba(57, 255, 20, 0.2)',
                        'rgba(255, 239, 0, 0.2)',
                        'rgba(255, 132, 19, 0.2)',
                        'rgba(255, 0, 0, 0.2)'
                    ],
                    borderColor: [
                        'rgba(57, 255, 20, 1)',
                        'rgba(255, 239, 0, 1)',
                        'rgba(255, 132, 19, 1)',
                        'rgba(255, 0, 0, 1)'
                        ],
                        borderWidth: 1
                    }],
                };

                const config = {
                    type: 'bar',  // Możesz zmienić typ wykresu na 'line', 'pie', itp.
                    data: chartData,
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                };

                const vulnerabilityChart = new Chart(ctx, config);
            })
            .catch(error => console.error('Error fetching chart data:', error));
    });
});
