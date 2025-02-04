import os
import psutil
import socket
import hashlib
import requests
import ctypes
import time
import subprocess
from prettytable import PrettyTable
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

# List of trusted publishers (you can add more)
TRUSTED_PUBLISHERS = ["Microsoft Corporation", "Intel Corporation", "Google LLC", "Apple Inc."]

# Function to get the path of the hashes.txt file relative to the script's location
def get_hashes_file_path():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "hashes.txt")

# Function to check if hash is in hashes.txt
def is_hash_in_file(process_hash):
    try:
        hashes_file_path = get_hashes_file_path()
        with open(hashes_file_path, "r") as f:
            hashes = f.readlines()
            for line in hashes:
                if process_hash.strip() == line.strip():
                    return True
        return False
    except FileNotFoundError:
        return False

# Function to get IP location
def get_ip_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        return response.get("city", "Unknown")
    except:
        return "Unknown"

# Function to compute the SHA-256 hash of an executable
def get_process_hash(exe_path):
    try:
        with open(exe_path, "rb") as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
            return file_hash.hexdigest()
    except:
        return "Unable to hash"

# Function to get the publisher using PowerShell
def get_publisher(exe_path):
    try:
        cmd = f'(Get-Item "{exe_path}").VersionInfo.CompanyName'
        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
        publisher = result.stdout.strip()
        return publisher if publisher else "Unknown Publisher"
    except:
        return "Unknown Publisher"

# Function to classify publisher trust level
def classify_publisher(publisher):
    if publisher in TRUSTED_PUBLISHERS:
        return "Trusted"
    elif publisher == "Unknown Publisher":
        return "Unknown"
    else:
        return "Third-party"

# Function to check if process is injected
def is_injected(pid, exe_path):
    try:
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        kernel32 = ctypes.windll.kernel32
        h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_process:
            return "Unknown"
        kernel32.CloseHandle(h_process)
        
        # Check if process hash exists in hashes.txt
        process_hash = get_process_hash(exe_path)
        if is_hash_in_file(process_hash):
            return "Injected"
        
        return "Not Injected"
    except:
        return "Error Checking"

# Function to scan processes and display results
def scan_processes():
    table = PrettyTable()
    table.field_names = [
        Fore.GREEN + "EXE", 
        Fore.GREEN + "PID", 
        Fore.GREEN + "IP", 
        Fore.GREEN + "TCP/UDP", 
        Fore.GREEN + "IP Location", 
        Fore.GREEN + "Injected", 
        Fore.GREEN + "Publisher", 
        Fore.GREEN + "Trust", 
        Fore.GREEN + "Hash"
    ]
    
    while True:
        table.clear_rows()
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                exe = proc.info['exe'] or "Unknown"
                
                # Get network connections
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if conn.pid == pid and conn.status == psutil.CONN_ESTABLISHED:
                        ip = conn.raddr.ip if conn.raddr else "N/A"
                        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                        city = get_ip_location(ip) if ip != "N/A" else "Local"
                        injected_status = is_injected(pid, exe)
                        publisher = get_publisher(exe)
                        trust_status = classify_publisher(publisher)
                        hash_value = get_process_hash(exe)
                        
                        # Add row to table
                        table.add_row([
                            Fore.GREEN + name, 
                            Fore.GREEN + str(pid), 
                            Fore.GREEN + ip, 
                            Fore.GREEN + protocol, 
                            Fore.GREEN + city,
                            Fore.GREEN + injected_status,
                            Fore.GREEN + publisher,
                            Fore.GREEN + trust_status,
                            Fore.GREEN + hash_value
                        ])
            except psutil.AccessDenied:
                continue
            except psutil.NoSuchProcess:
                continue
        
        print(table)
        time.sleep(5)  # Scan every 5 seconds

if __name__ == "__main__":
    scan_processes()