import ssl
import socket
from datetime import datetime

def get_tls_info(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check expiration
                not_after = cert.get('notAfter')
                valid = False
                if not_after:
                    expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y GMT')
                    valid = expire_date > datetime.utcnow()

                issuer = dict(x[0] for x in cert.get('issuer', []))
                
                return {
                    "valid": valid,
                    "issuer": issuer.get('organizationName', 'Unknown'),
                    "expiration": not_after,
                    "error": None
                }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "issuer": None, "expiration": None, "error": f"Cert verification failed: {e}"}
    except Exception as e:
        return {"valid": False, "issuer": None, "expiration": None, "error": str(e)}
