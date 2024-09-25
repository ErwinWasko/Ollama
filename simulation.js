document.addEventListener("DOMContentLoaded", function() {
    const cveSelect = document.getElementById('cve-select');
    const simulateAttackButton = document.getElementById('open-simulation');
    const simulationStepsContainer = document.getElementById('simulation-steps');
    const modal = document.getElementById("simulation-modal");                // Modal symulacji
    const closeSimulationButton = document.getElementById("close-simulation"); // Przycisk zamknięcia modala
    const svgContainer = document.getElementById('svg-container');            // Kontener SVG
    
    // Pobranie dostępnych CVE z backendu i wypełnienie listy rozwijanej
    fetch('/get_cve_list')
        .then(response => response.json())
        .then(data => {
            const cveList = data.cve_list;
            cveList.forEach(cve => {
                const option = document.createElement('option');
                option.value = cve;
                option.textContent = cve;
                cveSelect.appendChild(option);
            });
        })
        .catch(error => console.error('Błąd podczas pobierania listy CVE:', error));

    simulateAttackButton.addEventListener('click', function() {
        // Pobieramy wybrane CVE od użytkownika
        const selectedCve = cveSelect.value;

        fetch('/simulate_attack', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ vulnerability: selectedCve })
        })
        .then(response => response.json())
        .then(data => {
            const steps = data.steps;
            simulationStepsContainer.innerHTML = '';  // Wyczyść poprzednie kroki

            // Wyświetlamy kroki i uruchamiamy animację dla każdego kroku
            steps.forEach((step, index) => {
                const stepElement = document.createElement('p');
                stepElement.innerHTML = `Krok ${index + 1}: ${step}`;
                simulationStepsContainer.appendChild(stepElement);
            });

            // Otwórz modal po otrzymaniu danych
            modal.style.display = "block";

            // Uruchamiamy animację GSAP krok po kroku
            animateAttack(steps);
        })
        .catch(error => console.error("Błąd podczas symulacji ataku:", error));
    });

    // Funkcja odpowiedzialna za animację kroków ataku
    function animateAttack(steps) {
        const timeline = gsap.timeline({ defaults: { duration: 1, ease: "power1.inOut" } });

        // Animacja dla kroków ataku
        timeline.to("#attack-line1", { strokeDashoffset: 0, duration: 1, delay: 0.5 });
        timeline.to("#attack-line2", { strokeDashoffset: 0, duration: 1, delay: 1 });

        // Możemy dodawać więcej kroków w zależności od scenariusza
        timeline.to("#server", { fill: "red", duration: 1 }, "+=1");  // Serwer jest "zaatakowany"
        timeline.to("#workstation", { fill: "yellow", duration: 1 }, "+=1");  // Przejście ataku do stacji roboczej
    }

    // Zamknij modal po kliknięciu na "x" i wyczyść dane
    closeSimulationButton.addEventListener("click", function() {
        modal.style.display = "none";
        resetSimulationData();  // Reset danych symulacji
    });

    // Zamknij modal po kliknięciu poza oknem modalnym
    window.addEventListener("click", function(event) {
        if (event.target === modal) {
            modal.style.display = "none";
            resetSimulationData();  // Reset danych symulacji
        }
    });

    // Funkcja czyszcząca dane symulacji
    function resetSimulationData() {
        simulationStepsContainer.innerHTML = '';  // Wyczyść poprzednie kroki
        svgContainer.innerHTML = `
            <svg id="attack-simulation" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 100">
                <line id="attack-line1" x1="10" y1="20" x2="190" y2="20" stroke="#007bff" stroke-width="4" stroke-dasharray="180" stroke-dashoffset="180" />
                <line id="attack-line2" x1="10" y1="40" x2="190" y2="40" stroke="#0056b3" stroke-width="4" stroke-dasharray="180" stroke-dashoffset="180" />
                <circle id="server" cx="50" cy="70" r="10" fill="#fff" stroke="#000" stroke-width="2" />
                <circle id="workstation" cx="150" cy="70" r="10" fill="#fff" stroke="#000" stroke-width="2" />
            </svg>
        `;  // Resetuj SVG do stanu początkowego
    }
});
