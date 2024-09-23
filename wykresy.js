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

                // Podział danych na kategorie: Critical, High, Medium, Low
                const criticalData = cvssData['Critical'];
                const highData = cvssData['High'];
                const mediumData = cvssData['Medium'];
                const lowData = cvssData['Low'];

                // Tworzenie wykresu Chart.js
                const ctx = document.getElementById('vulnerabilityChart').getContext('2d');

                const chartData = {
                    labels: ['Critical', 'High', 'Medium', 'Low'], // Nazwy kategorii CVSS
                    datasets: [
                        {
                            label: 'Critical',
                            data: [criticalData, 0, 0, 0], // Dane dla Critical
                            backgroundColor: 'rgba(255, 0, 0, 0.6)',  // Czerwony
                            borderColor: 'rgba(255, 0, 0, 1)',
                            borderWidth: 2,
                            borderRadius: 5,
                            borderSkipped: false
                        },
                        {
                            label: 'High',
                            data: [0, highData, 0, 0], // Dane dla High
                            backgroundColor: 'rgba(255, 132, 19, 0.6)',  // Pomarańczowy
                            borderColor: 'rgba(255, 132, 19, 1)',
                            borderWidth: 2,
                            borderRadius: 5,
                            borderSkipped: false
                        },
                        {
                            label: 'Medium',
                            data: [0, 0, mediumData, 0], // Dane dla Medium
                            backgroundColor: 'rgba(255, 239, 0, 0.6)',  // Żółty
                            borderColor: 'rgba(255, 239, 0, 1)',
                            borderWidth: 2,
                            borderRadius: 5,
                            borderSkipped: false
                        },
                        {
                            label: 'Low',
                            data: [0, 0, 0, lowData], // Dane dla Low
                            backgroundColor: 'rgba(57, 255, 20, 0.6)',  // Zielony
                            borderColor: 'rgba(57, 255, 20, 0.6)',
                            borderWidth: 2,
                            borderRadius: 5,
                            borderSkipped: false
                        }
                    ]
                };

                const config = {
                    type: 'bar',  // Możesz zmienić typ wykresu na 'line', 'pie', itp.
                    data: chartData,
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'top',
                                labels: {
                                    font: {
                                        size: 14
                                    },
                                    padding: 20,
                                    boxWidth: 20
                                }
                            },
                            title: {
                                display: true,
                                text: 'Analiza Podatności wg CVSS',
                                font: {
                                    size: 18
                                },
                                padding: {
                                    top: 10,
                                    bottom: 30
                                }
                            }
                        },
                        scales: {
                            x: {
                                grid: {
                                    display: false
                                },
                                ticks: {
                                    font: {
                                        size: 14
                                    }
                                }
                            },
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(200, 200, 200, 0.3)'
                                },
                                ticks: {
                                    font: {
                                        size: 14
                                    }
                                }
                            }
                        },
                        layout: {
                            padding: {
                                left: 20,
                                right: 20,
                                top: 10,
                                bottom: 10
                            }
                        }
                    }
                };

                const vulnerabilityChart = new Chart(ctx, config);
            })
            .catch(error => console.error('Error fetching chart data:', error));
    });
});
