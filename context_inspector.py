import requests

def inspect_web_context(url="http://127.0.0.1:3000"):
    """
    Directly inspects the target to gather real DCS and ASS data.
    """
    print(f"[*] Context Agent: Inspecting headers for {url}...")
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        # Logic for DCS (Deployment Context Score)
        # We look for missing security headers or server signatures
        dcs_score = 10.0 # Start at max risk
        if 'X-Frame-Options' in headers: dcs_score -= 2.0
        if 'Content-Security-Policy' in headers: dcs_score -= 3.0
        if 'Server' in headers and "Express" in headers['Server']:
            print("[!] Server signature leaked: Node.js Express detected.")
            
        # Logic for ASS (Authentication & Session State)
        # Check if the page redirects to a login or has 'Set-Cookie'
        requires_auth = 10.0 if response.status_code == 401 else 5.0
        
        return {
            "dcs": round(max(dcs_score, 1.0), 2),
            "ass": requires_auth,
            "headers": dict(headers)
        }
    except Exception as e:
        print(f"[!] Context Inspection failed: {e}")
        return {"dcs": 5.0, "ass": 5.0, "headers": {}}
