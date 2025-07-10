from flask import Flask, request, jsonify
import requests
import logging
import os
import platform
import subprocess
import psutil
import json
import re
from datetime import datetime
from flask_cors import CORS
import pkg_resources
#import winreg
import sys

app = Flask(__name__)
CORS(app)

if platform.system().lower() == "windows":
    import winreg


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# NVD API configuration
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.environ.get("NVD_API_KEY", "ec2a5f46-20bf-4a19-b464-4cd444c270a9")

class SystemInventory:
    def __init__(self):
        self.os_type = platform.system().lower()
        
    def get_system_info(self):
        """Collect comprehensive system information"""
        try:
            info = {
                "timestamp": datetime.now().isoformat(),
                "hostname": platform.node(),
                "os": {
                    "name": platform.system(),
                    "version": platform.version(),
                    "release": platform.release(),
                    "architecture": platform.architecture()[0],
                    "processor": platform.processor(),
                    "machine": platform.machine()
                },
                "hardware": {
                    "cpu_count": psutil.cpu_count(logical=False),
                    "cpu_count_logical": psutil.cpu_count(logical=True),
                    "memory_total": psutil.virtual_memory().total,
                    "memory_available": psutil.virtual_memory().available,
                    "disk_usage": []
                },
                "network": {
                    "interfaces": []
                },
                "installed_software": [],
                "python_packages": [],
                "system_packages": []
            }
            
            # Get disk usage
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    info["hardware"]["disk_usage"].append({
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free
                    })
                except PermissionError:
                    continue
                    
            # Get network interfaces
            for interface, addresses in psutil.net_if_addrs().items():
                interface_info = {"name": interface, "addresses": []}
                for addr in addresses:
                    interface_info["addresses"].append({
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast
                    })
                info["network"]["interfaces"].append(interface_info)
                
            # Get installed software based on OS
            info["installed_software"] = self.get_installed_software()
            info["python_packages"] = self.get_python_packages()
            info["system_packages"] = self.get_system_packages()
            
            return info
            
        except Exception as e:
            logger.error(f"Error collecting system info: {str(e)}")
            return {"error": str(e)}
    
    def get_installed_software(self):
        """Get installed software based on operating system"""
        software = []
        
        try:
            if self.os_type == "windows":
                software = self.get_windows_software()
            elif self.os_type == "darwin":  # macOS
                software = self.get_macos_software()
            elif self.os_type == "linux":
                software = self.get_linux_software()
        except Exception as e:
            logger.error(f"Error getting installed software: {str(e)}")
            
        return software
    
    def get_windows_software(self):
        """Get installed software on Windows"""
        software = []
        
        try:
            # Check both 32-bit and 64-bit registry keys
            registry_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            
            for reg_path in registry_paths:
                try:
                    registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    for i in range(winreg.QueryInfoKey(registry_key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(registry_key, i)
                            subkey = winreg.OpenKey(registry_key, subkey_name)
                            
                            try:
                                display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                try:
                                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                except FileNotFoundError:
                                    version = "Unknown"
                                
                                try:
                                    publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                                except FileNotFoundError:
                                    publisher = "Unknown"
                                
                                software.append({
                                    "name": display_name,
                                    "version": version,
                                    "publisher": publisher,
                                    "type": "application"
                                })
                            except FileNotFoundError:
                                pass
                            
                            winreg.CloseKey(subkey)
                        except Exception:
                            continue
                    
                    winreg.CloseKey(registry_key)
                except Exception:
                    continue
                    
        except Exception as e:
            logger.error(f"Error getting Windows software: {str(e)}")
            
        return software
    
    def get_macos_software(self):
        """Get installed software on macOS"""
        software = []
        
        try:
            # Get applications from /Applications
            result = subprocess.run(
                ["find", "/Applications", "-name", "*.app", "-maxdepth", "2"],
                capture_output=True, text=True
            )
            
            for app_path in result.stdout.strip().split('\n'):
                if app_path:
                    app_name = os.path.basename(app_path).replace('.app', '')
                    # Try to get version from Info.plist
                    plist_path = os.path.join(app_path, "Contents", "Info.plist")
                    version = "Unknown"
                    
                    try:
                        plist_result = subprocess.run(
                            ["plutil", "-p", plist_path],
                            capture_output=True, text=True
                        )
                        
                        for line in plist_result.stdout.split('\n'):
                            if 'CFBundleShortVersionString' in line:
                                version = line.split('"')[3] if '"' in line else "Unknown"
                                break
                    except:
                        pass
                    
                    software.append({
                        "name": app_name,
                        "version": version,
                        "publisher": "Unknown",
                        "type": "application"
                    })
            
            # Get Homebrew packages
            try:
                result = subprocess.run(["brew", "list", "--versions"], 
                                     capture_output=True, text=True)
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            software.append({
                                "name": parts[0],
                                "version": parts[1],
                                "publisher": "Homebrew",
                                "type": "package"
                            })
            except:
                pass
                
        except Exception as e:
            logger.error(f"Error getting macOS software: {str(e)}")
            
        return software
    
    def get_linux_software(self):
        """Get installed software on Linux"""
        software = []
        
        try:
            # Try different package managers
            package_managers = [
                {"cmd": ["dpkg", "-l"], "type": "dpkg"},
                {"cmd": ["rpm", "-qa"], "type": "rpm"},
                {"cmd": ["pacman", "-Q"], "type": "pacman"},
                {"cmd": ["zypper", "search", "--installed-only"], "type": "zypper"}
            ]
            
            for pm in package_managers:
                try:
                    result = subprocess.run(pm["cmd"], capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        if pm["type"] == "dpkg":
                            for line in result.stdout.split('\n')[5:]:  # Skip header
                                if line.strip():
                                    parts = line.split()
                                    if len(parts) >= 3 and parts[0] == "ii":
                                        software.append({
                                            "name": parts[1],
                                            "version": parts[2],
                                            "publisher": "System",
                                            "type": "package"
                                        })
                        elif pm["type"] == "rpm":
                            for line in result.stdout.split('\n'):
                                if line.strip():
                                    software.append({
                                        "name": line.strip(),
                                        "version": "Unknown",
                                        "publisher": "System",
                                        "type": "package"
                                    })
                        elif pm["type"] == "pacman":
                            for line in result.stdout.split('\n'):
                                if line.strip():
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        software.append({
                                            "name": parts[0],
                                            "version": parts[1],
                                            "publisher": "System",
                                            "type": "package"
                                        })
                        break  # Found working package manager
                        
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue
                    
        except Exception as e:
            logger.error(f"Error getting Linux software: {str(e)}")
            
        return software
    
    def get_python_packages(self):
        """Get installed Python packages"""
        packages = []
        
        try:
            installed_packages = pkg_resources.working_set
            for package in installed_packages:
                packages.append({
                    "name": package.project_name,
                    "version": package.version,
                    "location": package.location,
                    "type": "python_package"
                })
        except Exception as e:
            logger.error(f"Error getting Python packages: {str(e)}")
            
        return packages
    
    def get_system_packages(self):
        """Get system-level packages and services"""
        packages = []
        
        try:
            # Get running services
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    packages.append({
                        "name": proc.info['name'],
                        "pid": proc.info['pid'],
                        "user": proc.info['username'],
                        "type": "service"
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"Error getting system packages: {str(e)}")
            
        return packages

# Initialize inventory collector
inventory = SystemInventory()

@app.route('/api/system-info', methods=['GET'])
def get_system_info():
    """Get comprehensive system information"""
    try:
        info = inventory.get_system_info()
        return jsonify(info)
    except Exception as e:
        logger.error(f"Error in system info endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Fetch vulnerabilities based on query parameters"""
    try:
        # Get query parameters
        cpe_name = request.args.get('cpeName')
        cve_id = request.args.get('cveId')
        keyword = request.args.get('keyword')
        severity = request.args.get('severity')
        results_per_page = request.args.get('resultsPerPage', '20')
        has_kev = request.args.get('hasKev', 'false').lower() == 'true'
        
        # Build query parameters for NVD API
        params = {}
        headers = {"apiKey": API_KEY}
        
        if cpe_name:
            params['cpeName'] = cpe_name
        if cve_id:
            params['cveId'] = cve_id
        if keyword:
            params['keywordSearch'] = keyword
        if severity:
            params['cvssV3Severity'] = severity
        if has_kev:
            params['hasKev'] = ''
        
        params['resultsPerPage'] = results_per_page
        
        # Make request to NVD API
        logger.info(f"Making request to NVD API with parameters: {params}")
        response = requests.get(NVD_API_BASE_URL, params=params, headers=headers)
        
        # Check if request was successful
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            logger.error(f"NVD API request failed with status code {response.status_code}")
            return jsonify({"error": f"NVD API request failed with status code {response.status_code}"}), 500
            
    except Exception as e:
        logger.error(f"Error processing vulnerability request: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan-vulnerabilities', methods=['POST'])
def scan_vulnerabilities():
    """Scan vulnerabilities for installed software"""
    try:
        # Get system information
        system_info = inventory.get_system_info()
        
        if "error" in system_info:
            return jsonify({"error": system_info["error"]}), 500
        
        vulnerabilities = []
        
        # Scan installed software
        for software in system_info.get("installed_software", []):
            software_name = software.get("name", "").lower()
            
            # Skip system components and common applications
            if any(skip in software_name for skip in ['microsoft', 'windows', 'kb', 'update']):
                continue
                
            # Search for vulnerabilities
            try:
                params = {
                    'keywordSearch': software_name,
                    'resultsPerPage': '10'
                }
                headers = {"apiKey": API_KEY}
                
                response = requests.get(NVD_API_BASE_URL, params=params, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    nvd_data = response.json()
                    
                    if nvd_data.get('vulnerabilities'):
                        for vuln in nvd_data['vulnerabilities']:
                            cve_data = vuln.get('cve', {})
                            vulnerabilities.append({
                                "software": software,
                                "cve_id": cve_data.get('id'),
                                "description": cve_data.get('descriptions', [{}])[0].get('value', 'N/A'),
                                "severity": get_severity(cve_data),
                                "published": cve_data.get('published'),
                                "modified": cve_data.get('lastModified')
                            })
                            
                # Rate limiting - small delay between requests
                import time
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error scanning {software_name}: {str(e)}")
                continue
        
        return jsonify({
            "scan_timestamp": datetime.now().isoformat(),
            "total_software": len(system_info.get("installed_software", [])),
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        })
        
    except Exception as e:
        logger.error(f"Error scanning vulnerabilities: {str(e)}")
        return jsonify({"error": str(e)}), 500

def get_severity(cve_data):
    """Extract severity from CVE data"""
    try:
        metrics = cve_data.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
        elif 'cvssMetricV30' in metrics:
            return metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
        elif 'cvssMetricV2' in metrics:
            return metrics['cvssMetricV2'][0]['baseSeverity']
    except:
        pass
    return "UNKNOWN"

@app.route('/api/cpe-format', methods=['POST'])
def format_cpe():
    """Format user input into proper CPE format"""
    try:
        data = request.json
        vendor = data.get('vendor', '*')
        product = data.get('product', '*')
        version = data.get('version', '*')
        part = data.get('part', 'a')  # Default to application
        
        # Format basic CPE 2.3 string
        cpe = f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*"
        
        return jsonify({"cpe": cpe})
        
    except Exception as e:
        logger.error(f"Error formatting CPE: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5002))
    app.run(host='0.0.0.0', port=port, debug=False)