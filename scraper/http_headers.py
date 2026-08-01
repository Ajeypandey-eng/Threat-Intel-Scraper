import requests

def get_security_headers(domain):
    url = f"https://{domain}"
    headers_to_check = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]
    
    results = {
        "headers": {},
        "error": None
    }
    
    try:
        response = requests.get(url, timeout=5)
        for h in headers_to_check:
            results["headers"][h] = response.headers.get(h)
    except requests.exceptions.SSLError:
        results["error"] = "SSL Error"
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            for h in headers_to_check:
                results["headers"][h] = response.headers.get(h)
        except Exception as e:
            results["error"] = f"SSL Error and HTTP fallback failed: {e}"
    except Exception as e:
        results["error"] = str(e)
        
    return results
