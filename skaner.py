import mysql.connector
from mysql.connector import Error
import requests
import ollama
import torch

# Funkcja łącząca się z bazą danych
def connect_to_database():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='test',
            user='root',
            password=''
        )
        return connection
    except Error as e:
        print(f"Error: {e}")
        return None

# Funkcja pobierająca raporty o podatnościach z bazy danych
def fetch_security_reports():
    connection = connect_to_database()
    if connection is None:
        return [], 0  # Zwraca pustą listę i 0, jeśli połączenie nie działa

    try:
        cursor = connection.cursor()
        query = """
        SELECT * 
        FROM vulnerabilities 
        ORDER BY CAST(vulnerability_score AS DECIMAL(3,1)) DESC
        """
        cursor.execute(query)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        return results
    except Error as e:
        print(f"Error: {e}")
        return [], 0
    finally:
        if connection:
            cursor.close()
            connection.close()

# Funkcja pobierająca szczegóły podatności z bazy danych na podstawie CVE
def fetch_vulnerability_details(cve):
    connection = connect_to_database()
    if connection is None:
        return None

    try:
        cursor = connection.cursor()
        query = """
        SELECT vulnerability_score, vulnerability_description
        FROM vulnerabilities 
        WHERE vulnerability = %s
        """
        cursor.execute(query, (cve,))
        result = cursor.fetchone()

        if result:
            # Rozdzielamy wyniki na odpowiednie zmienne
            cvss_score = result[0]
            description = result[1]
            return cvss_score, description  
        else:
            return None

    except Error as e:
        print(f"Error: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

# Pobieranie danych z MITRE
def fetch_mitre_data(cve):
    url = f'https://cveawg.mitre.org/api/cve/{cve}'
    try:
        response = requests.get(url)
        response.raise_for_status()
        mitre_data = response.json()
        
        if mitre_data and 'cveMetadata' in mitre_data:
            return mitre_data
        else:
            return None
    except requests.RequestException as e:
        print(f"Error fetching data from MITRE: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

# Przetwarzanie danych z MITRE
def process_mitre_data(mitre_data):
    if not mitre_data:
        return "No data available", []

    description = mitre_data.get('containers', {}).get('cna', {}).get('descriptions', [{'value': 'No description available'}])[0]['value']
    references = mitre_data.get('containers', {}).get('cna', {}).get('references', [])
    
    ref_urls = [ref['url'] for ref in references]
    
    return description, ref_urls

# Analiza danych przy użyciu Ollama
def analyze_data_with_ollama(cve, cvss, description, ref_urls):
    try:
        # Sprawdzenie dostępności GPU
        torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # Przygotowanie klienta Ollama
        client = ollama.Client()
        model_name = "llama3"

        # Konstruowanie promptu z uwzględnieniem danych z MITRE i referencji
        ref_text = "\n".join([f"- {url}" for url in ref_urls])
        prompt = f"""
        Here are the details of a vulnerability:
        CVE: {cve}
        CVSS Score: {cvss}
        Description: {description}
        
        Additionally, here are the reference URLs for further analysis:
        {ref_text}

        Please analyze this information and suggest specific steps to reduce the CVSS score and mitigate this vulnerability based on the content of the referenced pages. Please confirm that the analysis was conducted based on the provided URLs and summarize the conclusions drawn.
        """

        # Debugowanie promptu - upewnij się, że wyświetla się tylko raz
        print("Prompt for Ollama:", prompt)

        # Analiza danych
        response = client.generate(model=model_name, prompt=prompt)

        # Sprawdzamy strukturę odpowiedzi
        if isinstance(response, dict):
            if 'response' in response:
                text_response = response['response']
                filtered_response = ''.join(char for char in text_response if not char.isdigit())
                return f"Ollama has analyzed the provided URLs and drawn conclusions:\n{filtered_response.strip()}"
            else:
                print("No 'response' key in Ollama response.")
                return "No valid response from Ollama."
        else:
            print("Unexpected response format from Ollama.")
            return "No valid response from Ollama."

    except Exception as e:
        print(f"Error analyzing data with Ollama: {e}")
        return "No valid response from Ollama."

