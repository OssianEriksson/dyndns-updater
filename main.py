import requests
import json
import base64
import urllib
import sys
import threading

def get(url):
    response = requests.get(url)
    response.raise_for_status()

def cpanel(origin, domain, user, password):
    response = requests.get('https://api.ipify.org')
    response.raise_for_status()
    ip = response.content.decode('utf8')

    user = urllib.parse.quote(user)
    password = urllib.parse.quote(password)

    zone_name = ".".join(domain.split(".")[-2:])

    session = requests.Session()

    response = session.post(f"{origin}/login/?login_only=1", data=f"user={user}&pass={password}")
    response.raise_for_status()
    security_token = json.loads(response.content).get("security_token")
    if security_token is None:
        raise Exception("Unable to find security_token")

    response = session.post(f"{origin}{security_token}/execute/DNS/parse_zone", data=f"zone={zone_name}")
    response.raise_for_status()
    zone = json.loads(response.content)
    if not "data" in zone:
        raise Exception(f"Unable to find zone {zone_name}")
    soa_record = next((record for record in zone["data"] if record.get("record_type") == "SOA"), None)
    if soa_record == None:
        raise Exception("Unable to find SOA record")
    serial = int(base64.b64decode(soa_record["data_b64"][2]))
    a_record = next((record for record in zone["data"] if record.get("record_type") in ["A", "AAAA"] and base64.b64decode(record["dname_b64"]).decode("utf-8") == f"{domain}."), None)
    if soa_record == None:
        raise Exception(f"Unable to find A or AAAA record matching ip {ip}")
    ttl = a_record.get("ttl", 60)
    record_type = a_record.get("record_type", "AAAA" if ":" in ip else "A")
    line_index = a_record.get("line_index")
    if line_index is None:
        raise Exception(f"Unable to find line_index in zone {zone_name}")

    edit = urllib.parse.quote(f'{{"dname":"{domain}.","ttl":{ttl},"record_type":"{record_type}","line_index":{line_index},"data":["{ip}"]}}')
    response = session.post(f"{origin}{security_token}/execute/DNS/mass_edit_zone", data=f"zone={zone_name}&serial={serial}&edit={edit}")
    response.raise_for_status()

with open("/run/secrets/dyndns") as f:
    config = json.load(f)


def update_dns(service):
    try:
        print(f"Starting update of {service['name']}")
        if service["type"] == "get":
            get(service["url"])
        elif service["type"] == "cpanel":
            cpanel(service["origin"], service["domain"], service["user"], service["password"])
        else:
            raise Exception(f"Unknown service type {service['type']}")
    except Exception as e:
        print(e, file=sys.stderr)
    finally:
        print(f"Update of {service['name']} completed successfully")
    threading.Timer(service.get("rate", 300), lambda: update_dns(service)).start()

for service in config["services"]:
    update_dns(service)
