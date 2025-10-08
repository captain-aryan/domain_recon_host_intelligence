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
argparse.add_argument("-o", "--output", help="Enter the file to write output to")

# Parsing the arguments 
args = argparse.parse_args()
domain = args.domain
ip = args.shodan
output = args.output

# Whois module
print("[+] Getting whois info...")
whois_result = ''

# Whois Library instances
try:
    info = whois.query(domain)
    print("[+] Whois info found!")
    whois_result = f"Name: {info.name}" + '\n'
    whois_result += f"Registrar: {info.registrar}" + '\n'
    whois_result += f"Creation Date: {info.creation_date}" + '\n'
    whois_result += f"Expiration Date: {info.expiration_date}" + '\n'
    whois_result += f"Registrant: {info.registrant}" + '\n'
    whois_result += f"Registrant Country: {info.registrant_country}" + '\n'

except Exception as e:
    print(f"[-] Error getting whois info: {e}")
print(whois_result)

print()
# DNS Module
print("[+] Getting DNS info...")
dns_result = ''
# Implementing dns.resolver
try:
    for a in dns.resolver.resolve(domain, 'A'):
        dns_result = f"[+] A Record: {a.to_text()}" + '\n'
except Exception as a:
    print(f"[-] Error Fetching A Record! {a}")

try:
    for cname in dns.resolver.resolve(domain, 'CNAME'):
        dns_result += f"[+] A Record: {cname.to_text()}" + '\n'
except Exception as c:
    print(f"[-] Error Fetching CNAME Record! {c}")

try:
    for ns in dns.resolver.resolve(domain, 'NS'):
        dns_result += f"[+] NS Record: {ns.to_text()}" + '\n'
except Exception as n:
    print(f"[-] Error Fetching NS Record! {n}")

try:
    for mx in dns.resolver.resolve(domain, 'MX'):
        dns_result += f"[+] MX Record: {mx.to_text()}" + '\n'
except Exception as m:
    print(f"[-] Error Fetching MX Record! {m}")

try:
    for srv in dns.resolver.resolve(domain, 'SRV'):
        dns_result += f"[+] MX Record: {srv.to_text()}" + '\n'
except Exception as s:
    print(f"[-] Error Fetching SRV Record! {s}")

try:
    for txt in dns.resolver.resolve(domain, 'TXT'):
        dns_result += f"[+] TXT Record: {txt.to_text()}" + '\n'
except Exception as t:
    print(f"[-] Error Fetching TXT Record! {t}")
print(dns_result)

print()
# Geolocation Module
print("[+] Getting geolocation info...")
geo_result = ''
# Implementing requests for webrequests
try:
    response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    geo_result = f"[+] Country: {response['country_name']}"
except Exception as cntry:
    print(f"[-] Error Fetching Country {cntry}")

try:
    geo_result += f"[+] Latitude: {response['latitude']}" + '\n'
except Exception as lat:
    print(f"[-] Error Fetching Country {lat}")

try:
    geo_result += f"[+] Longitude: {response['longitude']}" + '\n'
except Exception as long:
    print(f"[-] Error Fetching Country {long}")

try:
    geo_result += f"[+] City: {response['city']}" + '\n'
except Exception as city:
    print(f"[-] Error Fetching Country {city}")

try:
    geo_result += f"[+] State: {response['state']}" + '\n'
except Exception as state:
    print(f"[-] Error Fetching Country {state}")
    
print(geo_result)

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

if (output):
    with open(output, 'w') as file:
        file.write(whois_result + '\n\n')
        file.write(dns_result + '\n\n')
        file.write(geo_result + '\n\n')