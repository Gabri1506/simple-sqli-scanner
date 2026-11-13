import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin
from playwright.sync_api import sync_playwright
import time
import json


HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

richieste = []

 
def chill_scan(url):
    i = 0
    print(f"[*] [L2] Static HTML analysis")
    inputs = []
    try:
        response = requests.get(url, headers=HEADERS, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        moltitag = soup.find_all(["input", "textarea", "select"])
        
        for tag in moltitag:
            tipo = (tag.get("type") or "text").lower()
            if tipo in ["submit", "button", "checkbox", "radio", "file"]:
                continue

            name = tag.get("name")
            id_tag = tag.get("id")
            placeholder = tag.get("placeholder")
            form = tag.find_parent("form")
            
            if form:
                endpoint = urljoin(url, form.get("action", ""))
                method = form.get("method", "POST").upper() 
            else:
                endpoint = url
                method = "POST" 

            nome = name or id_tag or placeholder
            if not nome:
                i += 1
                nome = f"Anonymous_n_{i}"
            
            inputs.append({
                "source": "html", 
                "name": nome.strip(), 
                "endpoint": endpoint,
                "method": method
            })
    except Exception as e:
        print(f"[!] Error L2: {e}")
    return inputs




def url_scan(url):
    print(f"[*] [L1] Parameter Analysis URL/Fragment...")
    inputs = []
    parsed = urlparse(url)
    urlbase = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    
    for i in parse_qs(parsed.query).keys():
        inputs.append({"source": "URL_Query", "name": i, "endpoint": urlbase, "method": "GET"})
    
    
    if "?" in parsed.fragment:
        try:
            query = parsed.fragment.split("?")[1]
            sottopagina = parsed.fragment.split("?")[0]
            endpoint = f"{urlbase}#{sottopagina}" 
            for i in parse_qs(query).keys():
                inputs.append({"source": "URL_Fragment", "name": i, "endpoint": endpoint, "method": "GET"})
        except: pass
    return inputs



def useapi(request):
    urlow = request.url.lower()
    if request.resource_type not in ["xhr", "fetch"]:
        return False
    
    
    blacklist = ["analytics", "google-analytics", "fonts", "i18n", "languages", "css", "svg", "png"]    
    for j in blacklist:
    
        if j in urlow:    
            return False  
   
    return True



def miniburp(request):  # Function to intercept requests (mini Burp)
    global richieste                     
    

    if not useapi(request):
        return

    testo = ""
    if request.post_data:
        testo = request.post_data
                
    richieste.append({
        "url": request.url,
        "method": request.method.upper(),
        "testo": testo,
        "headers": request.headers
    })
 
        


def browser_scan(url):

    print(f"[*] [L3] Dynamic Analysis on: {url}")
    target = []
    global richieste
    richieste = []

    with sync_playwright() as p:


        browser = p.chromium.launch(headless=True)
        sessione = browser.new_context(user_agent=HEADERS["User-Agent"])
        page = sessione.new_page()

        
        page.on("request", miniburp)
       

        

        try:
            page.goto(url, wait_until="networkidle", timeout=15000)
            
            
            inputs = page.query_selector_all("input:not([type='submit']):not([type='button']), textarea, [role='textbox']")  
            
            k = 0
            for inp in inputs:

                prova = f"BOEH_{k}" 
                k += 1
                try:
                    inp.fill(prova)   
                   
                    inp.press("Enter")  
                    time.sleep(0.5)
                except: continue


            bottoni = "button, input[type='submit'], [onclick], [role='button'], .btn, a[href^='javascript:']"

            pulsanti = page.query_selector_all(bottoni)

            for p in pulsanti:
                try:
                   
                    has_onclick = p.get_attribute("onclick") is not None
                    testo = (p.inner_text() or "").lower()
                    
                    clicca = False
                    if has_onclick:
                        clicca = True
                    else:
                        
                        for k in ["invia", "submit", "send", "login"]:
                            if k in testo:
                                clicca = True
                                break 

                   
                    if clicca:
                        p.click()
                        page.wait_for_timeout(1000)

                except:
                    continue



           
            for req in richieste: 

                stringa = str(req["testo"])
                
                try:                                    
                    data = json.loads(stringa)      

                    for key, value in data.items():  
                        if "BOEH" in str(value):

                            target.append({
                                "name": key,
                                "endpoint": req["url"],
                                "method": req["method"],
                                "type": "json",
                                "headers": req["headers"]
                            })


                except: 
                   
                    if "BOEH" in stringa and "=" in stringa:  
                        for parte in stringa.split("&"):  

                            if "=" in parte:       
                                key, value = parte.split("=", 1)

                                if "BOEH" in value:     
                                    target.append({
                                        "name": key,
                                        "endpoint": req["url"],
                                        "method": req["method"],
                                        "type": "form",
                                        "headers": req["headers"]
                                    })


            
            if not target:   
                forms = page.query_selector_all("form")

                for f in forms:

                    action = f.get_attribute("action")
                    
                    if action:
                        endpoint =  urljoin(url, action)
                    else:
                        endpoint = url

                  
                    method = (f.get_attribute("method") or "GET").upper()
                    
                    target.append({
                        "name": "anonimo", 
                        "endpoint": endpoint,
                        "method": method,
                        "type": "form"
                    })

        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            browser.close()
    munici = {}

    for t in target:     
        chiave = (t["name"], t["endpoint"], t["method"])
        munici[chiave] = t

    unici = list(munici.values())

    return list(unici)
