import whois
from datetime import datetime

def get_whois_data(domain):
    try:
        w = whois.whois(domain)
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        age_days = None
        if creation_date:
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            age_days = (datetime.now() - creation_date).days

        return {
            "registrar": w.registrar,
            "creation_date": str(creation_date) if creation_date else None,
            "expiration_date": str(expiration_date) if expiration_date else None,
            "age_days": age_days,
            "error": None
        }
    except Exception as e:
        return {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "age_days": None,
            "error": str(e)
        }
