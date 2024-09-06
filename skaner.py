import mysql.connector
from mysql.connector import Error
import requests
from bs4 import BeautifulSoup
import ollama
import torch
from vulners import VulnersApi

# Klucze API
FEEDLY_ACCESS_TOKEN = 'fe_SkA8e095YN1G03KLhR8IoaOqV4T5xbk8ZsguiLwf'

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
        FROM securityreports 
        ORDER BY CAST(cvss AS DECIMAL(3,1)) DESC
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

def initialize_vulners_api(api_key):
    try:
        return VulnersApi(api_key=api_key)
    except Exception as e:
        print(f"Error initializing Vulners API: {e}")
        return None

def fetch_vulners_data(cve):
    api_key = "PH8H76HM2HV9WSAEB62S7FODG99C0LGC2428N54GWQ64B4HUDTRQU2PAMEBP9DV9"  # Wstaw nowy klucz API Vulners tutaj
    vulners_api = initialize_vulners_api(api_key)
    
    if not vulners_api:
        return None
    
    try:
        # Pobieranie informacji o CVE
        result = vulners_api.get_bulletin(cve)
        
        # Debugowanie odpowiedzi
        print("Vulners API response:", result)
        
        if result and 'data' in result:
            return result['data']
        else:
            print(f"No data found for CVE: {cve}")
            return None
    except requests.RequestException as e:
        print(f"Failed to retrieve data from Vulners: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def process_vulners_data(vulners_data):
    if not vulners_data:
        return "No data available"

    # Przykład przetwarzania danych
    description = vulners_data.get('description', 'No description available')
    link = vulners_data.get('link', 'No link available')

    # Przetworzone dane do wyników analizy
    analysis_results = f"Description: {description}\nLink: {link}"
    
    return analysis_results


# Funkcja pobierająca dane z MITRE CVE API
def fetch_mitre_data(cve):
    url = f'https://cveawg.mitre.org/api/cve-id/{cve}'
    try:
        response = requests.get(url)
        response.raise_for_status()  # Sprawdź, czy zapytanie zakończyło się błędem
        mitre_data = response.json()
        return mitre_data
    except requests.RequestException as e:
        print(f"Error fetching data from MITRE: {e}")
        return None

# Funkcja przetwarzająca dane z MITRE CVE API
def process_mitre_data(mitre_data):
    if mitre_data:
        cve_id = mitre_data.get('cveMetadata', {}).get('cveId', 'N/A')
        description = mitre_data.get('containers', {}).get('cna', {}).get('descriptions', [{'value': 'No description available'}])[0]['value']
        references = mitre_data.get('containers', {}).get('cna', {}).get('references', [])
        
        ref_text = "\n".join([f"- {ref['url']}" for ref in references]) if references else "No references available."
        
        return f"Details from MITRE CVE:\nCVE ID: {cve_id}\nDescription: {description}\nReferences:\n{ref_text}"
    else:
        return "Failed to retrieve valid data from MITRE."

# Funkcja pobierająca dane z Feedly API
def fetch_feedly_data(cve):
    url = 'https://cloud.feedly.com/v3/search/contents'
    headers = {
        'Authorization': f'Bearer {FEEDLY_ACCESS_TOKEN}'
    }
    params = {
        'query': cve,
        'count': 5  # Liczba artykułów do pobrania
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Sprawdź, czy zapytanie zakończyło się błędem
        feedly_data = response.json()
        return feedly_data
    except requests.RequestException as e:
        print(f"Error fetching data from Feedly: {e}")
        return None

# Funkcja przetwarzająca dane z Feedly w celu wygenerowania czytelnej odpowiedzi tekstowej
def process_feedly_data(feedly_data):
    if feedly_data and 'items' in feedly_data:
        items = feedly_data['items']
        if not items:
            return "No relevant articles found in Feedly."
        
        articles = [f"Title: {item.get('title', 'No title available')}\nLink: {item.get('originId', 'No link available')}" for item in items]
        return "\n\n".join(articles)
    else:
        return "Failed to retrieve valid data from Feedly."

        # Funkcja pobierająca dane z Exploit-DB
def fetch_exploit_db_data(cve):
    url = f"https://www.exploit-db.com/search?q={cve}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Sprawdź, czy zapytanie zakończyło się błędem
        
        soup = BeautifulSoup(response.text, 'html.parser')

        
        table = soup.find('table', {'id': 'exploits-table'})
        
        # Sprawdzenie, czy tabela istnieje
        if not table:
            print("No exploits table found in Exploit-DB HTML.")
            return "No exploits found for this CVE in Exploit-DB."
        
        # Znalezienie wszystkich wierszy tabeli, bez względu na istnienie tbody
        rows = table.find_all('tr')
        if not rows:
            return "No exploits found for this CVE in Exploit-DB."

        exploits = []
        for row in rows[1:6]:  # Pomijamy pierwszy wiersz, który zazwyczaj zawiera nagłówki
            columns = row.find_all('td')
            if len(columns) > 1:
                title = columns[1].get_text(strip=True)
                link = f"https://www.exploit-db.com{columns[1].find('a')['href']}"
                date = columns[2].get_text(strip=True)
                exploits.append(f"Title: {title}\nDate: {date}\nLink: {link}")
        
        if not exploits:
            return "No exploits found for this CVE in Exploit-DB."
        
        return "\n\n".join(exploits)
    
    except requests.RequestException as e:
        print(f"Error fetching data from Exploit-DB: {e}")
        return "Failed to retrieve data from Exploit-DB."

# Funkcja analizująca dane przy użyciu Ollama API
def analyze_data_with_ollama(cve, cvss, description, vulners_data, mitre_data, feedly_data, exploit_db_data):
    try:
        # Sprawdzenie dostępności GPU
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        if device.type == 'cuda':
            print("GPU has been successfully loaded and is available.")
        else:
            print("GPU is not available. Running on CPU.")

        # Przygotowanie klienta Ollama
        client = ollama.Client()
        model_name = "llama3"

        # Konstruowanie promptu z uwzględnieniem danych z Vulners, MITRE, Feedly i Exploit-DB
        prompt = f"""
        Here are the details of a vulnerability:
        CVE: {cve}
        CVSS Score: {cvss}
        Description: {description}

        Additionally, here is the data retrieved from Vulners for further analysis:
        {vulners_data}
        
        Additionally, here is the data retrieved from MITRE CVE for further analysis:
        {mitre_data}

        Additionally, here are the latest articles from Feedly related to this CVE:
        {feedly_data}

        Additionally, here are the latest exploits found in Exploit-DB related to this CVE:
        {exploit_db_data}

        Please analyze this information and suggest specific steps to reduce the CVSS score and mitigate this vulnerability.
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
                return filtered_response.strip()
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
    
    # Znalezienie raportu o najwyższym wskaźniku CVSS
    highest_cvss_report = max(reports, key=lambda r: float(r.get('cvss', 0)))
    
    # Pobieranie poziomu CVSS i opisu
    cvss = highest_cvss_report.get('cvss', 'N/A')
    description = highest_cvss_report.get('description', 'No description available')
    
    # Pobieranie danych z Vulners API
    cve = highest_cvss_report.get('cve')
    if cve is None:
        print("CVE key is missing in highest CVSS report")
        return
    
    vulners_data = fetch_vulners_data(cve)
    if vulners_data is None:
        print(f"Failed to fetch data from Vulners for CVE: {cve}")
        vulners_analysis = "No data available from Vulners."
    else:
        # Przetwarzanie danych z Vulners
        vulners_analysis = process_vulners_data(vulners_data)
    
    # Pobieranie danych z MITRE CVE API
    mitre_data = fetch_mitre_data(cve)
    if mitre_data is None:
        mitre_analysis = "CVE not found in MITRE database."
    else:
        # Przetwarzanie danych z MITRE
        mitre_analysis = process_mitre_data(mitre_data)
    
    # Pobieranie danych z Feedly
    feedly_data = fetch_feedly_data(cve)
    if feedly_data is None:
        print(f"Failed to fetch data from Feedly for CVE: {cve}")
        feedly_analysis = "No articles found in Feedly."
    else:
        # Przetwarzanie danych z Feedly
        feedly_analysis = process_feedly_data(feedly_data)
    
    # Pobieranie danych z Exploit-DB
    exploit_db_data = fetch_exploit_db_data(cve)
    if exploit_db_data is None:
        print(f"Failed to fetch data from Exploit-DB for CVE: {cve}")
        exploit_db_data = "No exploits found in Exploit-DB."
    
    # Analiza danych przy użyciu Ollama API
    ollama_analysis = analyze_data_with_ollama(cve, cvss, description, vulners_analysis, mitre_analysis, feedly_analysis, exploit_db_data)
    
    # Wyświetl wyniki
    print(f"Report for CVE: {cve}")
    print("Ollama Analysis:")
    if ollama_analysis:
        print(ollama_analysis)  # Wyświetl odpowiedź Ollama
    else:
        print("No analysis available")
    print("\n")
    
    print("Vulners Analysis:")
    print(vulners_analysis)  # Wyświetl przetworzoną analizę danych z Vulners

    data = fetch_vulners_data(cve)
    if data:
        processed_data = process_vulners_data(data)
        print(processed_data)
    else:
        print("Failed to fetch or process data.")
    
    print("MITRE Analysis:")
    print(mitre_analysis)  # Wyświetl przetworzoną analizę danych z MITRE

    print("Feedly Analysis:")
    print(feedly_analysis)  # Wyświetl przetworzoną analizę danych z Feedly
    
    print("Exploit-DB Analysis:")
    print(exploit_db_data)  # Wyświetl przetworzoną analizę danych z Exploit-DB
    print("\n")

if __name__ == "__main__":
    main()
