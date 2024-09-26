document.addEventListener("DOMContentLoaded", function() {
    const printPdfButton = document.getElementById('print-pdf');
    const printWordButton = document.getElementById('print-word');

    printPdfButton.addEventListener("click", function() {
        const reports = window.allReports || [];  // Użycie zmiennej globalnej
        if (reports.length === 0) {
            alert('No reports to print.');
            return;
        }

        fetch('/generate_pdf_report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ reports })
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

    printWordButton.addEventListener("click", function() {
        const reports = window.allReports || [];
        if (reports.length === 0) {
            alert('No reports to print.');
            return;
        }

        fetch('/generate_word_report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ reports })
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
});
