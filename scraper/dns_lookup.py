import dns.resolver

def get_dns_records(domain):
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "error": None
    }
    try:
        for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [rdata.to_text() for rdata in answers]
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                records["error"] = "Domain does not exist."
                break
            except Exception:
                pass
    except Exception as e:
        records["error"] = str(e)
        
    return records
