Domain Recon and Host Intelligence Tool

usage: python3 main.info -d DOMAIN [-s IP] 

options:
  -h, --help           show this help message and exit
  -d, --domain DOMAIN  Enter the domain name
  -s, --shodan SHODAN  Enter the IP for shodan search
  -o, --output OUTPUT  Enter the file to write output to

If you want to use the whois library specifically on Windows, you need to install the Windows whois command-line tool.
Download: Go to https://learn.microsoft.com/en-us/sysinternals/downloads/whois
Extract: Unzip the downloaded file to get whois.exe
Put whois.exe in the same directory where your main.py is present