document.addEventListener("DOMContentLoaded", function() {
    const sendMessageButton = document.getElementById('send-message');
    const chatInput = document.getElementById('chat-input');
    const chatMessages = document.getElementById('chat-messages');

    // Funkcja do wyświetlania wiadomości
    function displayMessage(message, className) {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('chat-message', className);
        messageDiv.textContent = message;
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight; // Automatyczne przewijanie
    }

    // Obsługa kliknięcia przycisku Wyślij
    sendMessageButton.addEventListener('click', function() {
        const userMessage = chatInput.value.trim();

        if (userMessage === '') {
            alert('Wpisz pytanie!');
            return;
        }

        // Wyświetlenie wiadomości użytkownika w oknie czatu
        displayMessage(userMessage, 'user-message');
        chatInput.value = '';

        // Wysłanie zapytania do backendu
        fetch('/ask_chatbot', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ question: userMessage }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.answer) {
                displayMessage(data.answer, 'bot-message');
            } else {
                displayMessage('Nie mogłem znaleźć odpowiedzi.', 'bot-message');
            }
        })
        .catch(error => {
            console.error("Błąd połączenia z serwerem:", error);
            displayMessage('Błąd połączenia z serwerem.', 'bot-message');
        });
    });
});
