import csv
import json
import logging
from abc import ABC, abstractmethod
from typing import List
from pathlib import Path
from portintel.models.schemas import PortResult
from portintel.config.settings import config

logger = logging.getLogger(__name__)

class BaseExporter(ABC):
    @abstractmethod
    def export(self, filename: str, open_ports: List[PortResult]):
        pass

class CSVExporter(BaseExporter):
    def export(self, filename: str, open_ports: List[PortResult]):
        path = Path(filename)
        # Ensure parent directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(path, mode='w', newline='', encoding='utf-8') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(['Port', 'Service', 'Version', 'Status', 'Banner', 'CVEs'])
                
                for pr in open_ports:
                    cves_str = ", ".join(pr.cves) if pr.cves else ""
                    writer.writerow([pr.port, pr.service, pr.version or "", pr.status, pr.banner or "", cves_str])
                    
            logger.info(f"\n[+] Scan results successfully exported to {path}")
        except Exception as e:
            logger.error(f"\n[-] Failed to export results to {path}: {e}")

class JSONExporter(BaseExporter):
    def export(self, filename: str, open_ports: List[PortResult]):
        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            data = []
            for pr in open_ports:
                data.append({
                    "port": pr.port,
                    "service": pr.service,
                    "version": pr.version or "",
                    "status": pr.status,
                    "banner": pr.banner or "",
                    "cves": pr.cves
                })
                
            with open(path, mode='w', encoding='utf-8') as json_file:
                json.dump(data, json_file, indent=4)
                
            logger.info(f"\n[+] Scan results successfully exported to {path}")
        except Exception as e:
            logger.error(f"\n[-] Failed to export results to {path}: {e}")

class ConsoleExporter(BaseExporter):
    def export(self, filename: str, open_ports: List[PortResult]):
        # The console exporter ignores the filename parameter
        if not open_ports:
            logger.info("No open ports found.")
            return

        logger.info(f"{'PORT':<6} {'SERVICE':<15} {'STATUS'}")
        logger.info("-" * 35)
        
        for pr in open_ports:
            logger.info(f"{pr.port:<6} {pr.service:<15} {pr.status}")
            
            if pr.version:
                logger.info(f"       |- Version: {pr.version}")
                
            if pr.banner:
                display_banner_str = pr.banner if len(pr.banner) <= 60 else pr.banner[:57] + "..."
                logger.info(f"       |- Banner: {display_banner_str}")
                
                if pr.cves:
                    logger.info(f"       |- Vulns : {', '.join(pr.cves)}")
