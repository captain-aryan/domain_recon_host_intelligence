import whois
import dns.resolver
import shodan
import requests
import argparse
import socket

argparse = argparse.ArgumentParser(description="Basic Information Gathering Tool", usage="python3 main.info -d DOMAIN [-s IP]")
# Arguments
argparse.add_argument("-d", "--domain", help="Enter the domain name", required=True)
argparse.add_argument("-s", "--shodan", help="Enter the IP for shodan search")

# Parsing the arguments 
args = argparse.parse_args()
domain = args.domain
ip = args.shodan

# Whois module
print("[+] Getting whois info...")

# Whois Library instances
try:
    info = whois.query(domain)
    print("[+] Whois info found!")
    print(f"Name: {info.name}")
    print(f"Registrar: {info.registrar}")
    print(f"Creation Date: {info.creation_date}")
    print(f"Expiration Date: {info.expiration_date}")
    print(f"Registrant: {info.registrant}")
    print(f"Registrant Country: {info.registrant_country}")

except Exception as e:
    print(f"[-] Error getting whois info: {e}")

print()
# DNS Module
print("[+] Getting DNS info...")

# Implementing dns.resolver
try:
    for a in dns.resolver.resolve(domain, 'A'):
        print(f"[+] A Record: {a.to_text()}")
except Exception as a:
    print(f"[-] Error Fetching A Record! {a}")

try:
    for cname in dns.resolver.resolve(domain, 'CNAME'):
        print(f"[+] A Record: {cname.to_text()}")
except Exception as c:
    print(f"[-] Error Fetching CNAME Record! {c}")

try:
    for ns in dns.resolver.resolve(domain, 'NS'):
        print(f"[+] NS Record: {ns.to_text()}")
except Exception as n:
    print(f"[-] Error Fetching NS Record! {n}")

try:
    for mx in dns.resolver.resolve(domain, 'MX'):
        print(f"[+] MX Record: {mx.to_text()}")
except Exception as m:
    print(f"[-] Error Fetching MX Record! {m}")

try:
    for srv in dns.resolver.resolve(domain, 'SRV'):
        print(f"[+] MX Record: {srv.to_text()}")
except Exception as s:
    print(f"[-] Error Fetching SRV Record! {s}")

try:
    for txt in dns.resolver.resolve(domain, 'TXT'):
        print(f"[+] TXT Record: {txt.to_text()}")
except Exception as t:
    print(f"[-] Error Fetching TXT Record! {t}")

print()
# Geolocation Module
print("[+] Getting geolocation info...")

# Implementing requests for webrequests
try:
    response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    print(f"[+] Country: {response['country_name']}")
except Exception as cntry:
    print(f"[-] Error Fetching Country {cntry}")

try:
    print(f"[+] Latitude: {response['latitude']}")
except Exception as lat:
    print(f"[-] Error Fetching Country {lat}")

try:
    print(f"[+] Longitude: {response['longitude']}")
except Exception as long:
    print(f"[-] Error Fetching Country {long}")

try:
    print(f"[+] City: {response['city']}")
except Exception as city:
    print(f"[-] Error Fetching Country {city}")

try:
    print(f"[+] State: {response['state']}")
except Exception as state:
    print(f"[-] Error Fetching Country {state}")
    
print()
# Shodan Module
if ip:
    print(f"[+] Getting info from Shodan for {ip}")
    api = shodan.Shodan("YOUR_API_KEY")  # Get your key from shodan.io
    
    try:
        # Check available credits first
        api_info = api.info()
        print(f"[+] Available Query Credits: {api_info['query_credits']}")
        
        # Get host information
        host = api.host(ip)
        
        print(f"\n[+] Shodan Results:")
        print(f"IP: {host['ip_str']}")
        print(f"Organization: {host.get('org', 'N/A')}")
        print(f"Operating System: {host.get('os', 'N/A')}")
        print(f"Country: {host.get('country_name', 'N/A')}")
        print(f"City: {host.get('city', 'N/A')}")
        print(f"ISP: {host.get('isp', 'N/A')}")
        print(f"Hostnames: {', '.join(host.get('hostnames', []))}")
        
        print(f"\n[+] Open Ports: {', '.join(str(item['port']) for item in host['data'])}")
        
        print(f"\n[+] Services:")
        for item in host['data']:
            print(f"    Port {item['port']}: {item.get('product', 'Unknown')}")
            
    except shodan.APIError as e:
        print(f"[-] Shodan API Error: {e}")
    except Exception as e:
        print(f"[-] Error: {e}")
else:
    print("[!] No IP provided for Shodan search. Use -s flag to specify an IP.")