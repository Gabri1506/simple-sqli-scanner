import recon
import scansql

#site used for test: https://juice-shop.herokuapp.com/#/search?q=g     https://juice-shop.herokuapp.com/#/login   https://demo.testfire.net/login.jsp 



target = "https://juice-shop.herokuapp.com/#/login"


print("""Choose the scan mode
      1. smart search, result from the first scan that find somethings
      2. deep search, joint result from all the scan together""")

mod = input()

if mod == 1:

    risultati = recon.url_scan(target)  


    if not risultati:
        risultati = recon.chill_scan(target)


    if not risultati:
        risultati = recon.browser_scan(target)


    if risultati:
        print(f"\n[V] find {len(risultati)} access points")
        for r in risultati:
            print(f"    - [Nome: {r['name']}")

    else:
        print("\n[!] No input found")



elif mod == 2:

    result0 = recon.browser_scan(target) +    recon.chill_scan(target) + recon.url_scan(target)  
    result1 = []
    nomi_visti = set()

    for r in result0:
        if r['name'] not in nomi_visti:
            result1.append(r)
            nomi_visti.add(r['name'])


    if result1:
        print(f"\n[V] find {len(result1)} access points")
        for r in result1:
        
    
            print(f"    - [Name: {r['name']}")
            print(f"{r["endpoint"]} , {r["method"]}")
            
           

    else:
        print("\n[!] No input found")



if (mod == 1 and risultati) or (mod == 2 and result1):
    input("\n[?] Recon complete. Press ENTER to start the SQLI test...")
    
    mod = input("""Choose the stealth level:
                    1. low (hardcoded headers and no cookies or csrf)
                    2. high (csrf token cookies captured from a real session, requires more resources)""")
    final_list = risultati if mod == 1 else result1

    scansql.start(final_list,mod)
else:
    print("\n[!] Test phase skipped: no input found.")
