import subprocess
import json

def run_nmap_discovery(target_ip="127.0.0.1", port="3000"):
    """
    Executes a service discovery scan on the target.
    This fulfills the 'Identify Attack Surface' role of the Discovery Agent.
    """
    print(f"[*] Discovery Agent: Scanning {target_ip}:{port}...")
    
    # Run Nmap with service detection (-sV) and output to XML
    # Using -oX - allows us to capture the output directly in Python
    cmd = ["nmap", "-sV", "-p", port, target_ip]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error during discovery: {e}"

if __name__ == "__main__":
    scan_results = run_nmap_discovery()
    print(scan_results)
