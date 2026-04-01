import requests
import json 
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv('VT_API_KEY')
URL = 'https://www.virustotal.com/api/v3/ip_addresses/'

headers = {

"x-apikey" : API_KEY

}

def check_ip(ip_address): 

    full_url = URL + ip_address 

    response = requests.get(full_url, headers=headers)

    if response.status_code == 200: 
        report = response.json()
        stats = report['data']['attributes']['last_analysis_stats']
        print(f"Result for IP : {ip_address}")
        print(f" -Malicious:{stats['malicious']}")
        print(f" -Suspicious:{stats['suspicious']}")
        print(f" -Undetected:{stats['undetected']}")

        if stats['malicious'] > 0:
            print("\n[!] WARNING: This IP is flagged as Malicious!")
        else: 
            print("\n[✓] This IP appears to be Clean.")
        return report 
    else: 
        print(f"Error occured: {response.status_code}")
        return None
    
target_ip = input("Enter an IP address to check:")
check_ip(target_ip)