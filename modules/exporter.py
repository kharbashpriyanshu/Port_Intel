import csv
import json
from modules.services import get_service_name

def export_to_csv(filename: str, open_ports: list):
    """
    Exports the list of discovered open ports to a CSV file.
    open_ports is expected to be a list of tuples: (port, banner)
    """
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            # Write the header row
            writer.writerow(['Port', 'Service', 'Status', 'Banner'])
            
            # Write the data rows
            for port, banner in open_ports:
                service = get_service_name(port)
                writer.writerow([port, service, 'OPEN', banner])
                
        print(f"\n[+] Scan results successfully exported to {filename}")
    except Exception as e:
        print(f"\n[-] Failed to export results to {filename}: {e}")

def export_to_json(filename: str, open_ports: list):
    """
    Exports the list of discovered open ports to a JSON file.
    """
    try:
        data = []
        for port, banner in open_ports:
            data.append({
                "port": port,
                "service": get_service_name(port),
                "status": "OPEN",
                "banner": banner
            })
            
        with open(filename, mode='w', encoding='utf-8') as json_file:
            json.dump(data, json_file, indent=4)
            
        print(f"\n[+] Scan results successfully exported to {filename}")
    except Exception as e:
        print(f"\n[-] Failed to export results to {filename}: {e}")
