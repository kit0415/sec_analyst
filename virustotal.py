import requests
import json

apikey = "83e54b3029eb3a1af0a75858981ba0a6605915d5cbb93bcb7005ce398c396192"

def scan_file(filepath):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': apikey}
    files = {'file': (filepath, open(filepath, 'rb'))}
    response = requests.post(url, files=files, params=params)
    data = response.json()
    resourceid = data['resource']
    return resourceid

def get_report(resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': apikey, 'resource': resource}

    response = requests.get(url, params=params)
    data = response.json()
    positiveFound = data['positives']
    print positiveFound

resource = scan_file("reverse.php")
get_report(resource)


