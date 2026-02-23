# shoodex
shoodex is a simple GUI tool that allows you to scan large lists of IP addresses using Shodan (no Shodan API key, no paid membership needed).

Just upload a TXT file containing IP addresses and start the scan. Results are streamed in real time and can be exported as a TXT file when the scan is complete. It can perform bulk scans of up to 500 IPs, this number might be infinite, but I haven't tested it.

![shoodex](shoodex.gif)

# Usage
1) pip install -r requirements.txt
2) Run python shoodex.py in the terminal and go to http://127.0.0.1:5000
3) Upload a TXT file and start the scan.

# Features
1) Mass IP scanning via Shodan
2) No API key required
3) No paid Shodan membership needed
4) Real‑time results
5) TXT output export
6) Easy web interface
7) Uses Shodan data for passive reconnaissance instead of scanning targets directly

Thanks to my team
1) For frontend: Cursor cooked it
2) For backend: Claude did the heavy lifting

For educational and authorized security testing only.
