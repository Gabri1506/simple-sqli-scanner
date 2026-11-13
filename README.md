# simple-sqli-scanner
A Python-based reconnaissance and SQL Injection vulnerability scanner supporting static HTML, URL fragments, and Playwright dynamic analysis.

Overview

this tool is an automated security tool designed to identify and test injection points within web applications. It goes beyond static analysis by combining traditional crawling with dynamic browser emulation to uncover hidden parameters and API endpoints

Prerequisites

Python 3.14

core libraries
- requests: for http communication
- BeatifulSoup: for html parsing
- playwirght: for browser automation

built in module: urllib3, time, json, re, concurrent.futures

How it works

1. Reconnaissance (Multi-Tier Discovery)
the tool start scanning the given url for input boxes and it does it in three way:
    a. html scanning: the tool parse the html of the website and search for standard input tags 
    b. url analysis: the tool parse and deconstructs the url, search and extrac any query inside it
    c. dynamic browser interception: the tool simulate a real user through playwright, manually sending a test text and once capture the requests it search the text test inside the various requests, it also search if there are any api for send the input

Data Captured per Entry Point:
- Parameter Name (Auto-labels as anonymous_n if missing).
- target endpoint 
- the method (GET/POST/PUT)
- the content type (form or json, only for browser scan)
- the required headers


2. Injection Engine

    a. preparation:
      - Deduplication: the tool after receiving the information about the input boxes tries to remove possible duplicates (if something was find).

      - Session camouflage: start a browser session where it extract hte csrf and cookie (if the mode is choose) for then use it to simulate a real user and don't get blocked easily by possible antibot security of the target website.
      - Baseline Calculation: Measures the server’s latency under normal conditions (baseline). The baseline will be use after for searching possible time based sql vulnerabilities

    b. execution:
     the tool is now ready to send the requests with the payload and use ThreadPoolExecutor to run tasts in parallel (number of workers can be modified) where every input box found is tested with every payload. There are payload to detect with boolean type, time based or error based

    c. recognition:
     the tool now have all the information to see if the site is vulnerable to sql injection it check with:  
     1. error based: scans response bodies for database-specific syntax errors
     2. time based compares response times against the Baseline with a threshold of default + 4.5 s 
     3. boolean based watch the output status and the lenght of the site between a false payload and a true payload

3. output
Vulnerabilities are logged in real-time to the terminal, with:
    - Vulnerability Type (e.g., Time-Based).
    - Successful Payload used.
    - Target Parameter and Endpoint.




Usage

1. scan modes
- mode 1 Stops the reconnaissance phase as soon as the first entry point is found. It prioritizes speed and low resource consumption.
- mode 2 Executes all three scanning types (HTML, URL, Browser) and generates a target list without duplicates.


2. injection modes 
- mode 1 Sends requests using only captured headers and standard methods. Fastest, but can be blocked by anti bot website security
- mode 2 Activates Session Camouflage. Creates a temporary session to fetch valid CSRF tokens/cookies before launching the attack. 


Legal Disclaimer
IMPORTANT: This tool is developed for educational purposes and authorized ethical hacking/penetration testing only. Usage of this software against targets without explicit written permission is illegal and punishable by law. The developer assumes no liability for any misuse of this tool.
