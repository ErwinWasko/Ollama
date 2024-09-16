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

def process_mitre_data(mitre_data):
    if not mitre_data:
        return "No data available", []

    description = mitre_data.get('containers', {}).get('cna', {}).get('descriptions', [{'value': 'No description available'}])[0]['value']
    references = mitre_data.get('containers', {}).get('cna', {}).get('references', [])
    
    ref_urls = [ref['url'] for ref in references]
    
    return description, ref_urls

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
        
        # Debugowanie promptu
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

def main():
    # Pobieranie raportów o podatnościach
    reports = fetch_security_reports()
    
    if not isinstance(reports, list) or not reports:
        print("No security reports found.")
        return
    
    # Iterowanie przez wszystkie raporty
    for report in reports:
        cve = report.get('vulnerability')
        cvss = report.get('vulnerability_score', 'N/A')
        description = report.get('vulnerability_description', 'No description available')
        
        # Pobieranie danych z MITRE CVE API
        mitre_data = fetch_mitre_data(cve)
        description, ref_urls = process_mitre_data(mitre_data)
        
        # Analiza danych przy użyciu Ollama API
        ollama_analysis = analyze_data_with_ollama(cve, cvss, description, ref_urls)
        
        # Wyświetl wyniki
        print(f"Report for CVE: {cve}")
        print("Ollama Analysis:")
        print(ollama_analysis if ollama_analysis else "No analysis available")
        print("\n")

if __name__ == "__main__":
    main()
