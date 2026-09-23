import requests

def get_info_ip(IP):
    base_url = "https://api.ipinfo.io/lite/" # J'ai ajusté l'URL classique de l'API
    url = f"{base_url}{IP}?token=6be41dd4d85adb"
    
    try:
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            # Parfois l'API renvoie un 200 mais avec un message d'erreur interne
            if "error" in data:
                return {"error": data["error"].get("message", "Erreur API inconnue")}
            return data
            
        elif response.status_code == 401:
            return {"error": "Token API invalide."}
        elif response.status_code == 429:
            return {"error": "Limite de requêtes atteinte."}
        else:
            return {"error": f"Erreur serveur ({response.status_code})"}
            
    except requests.exceptions.RequestException as e:
        # On retourne l'erreur proprement au lieu de faire un print
        return {"error": f"Erreur réseau : impossible de joindre l'API."}

# -------------------------------------------------------------------
# Zone de test du module
# -------------------------------------------------------------------

if __name__ == "__main__": 

    # Le .strip() retire les espaces invisibles avant et après la saisie
    ip_adress = input("Entrez l'IP à analyser : ").strip()
    
    # Sécurité : on vérifie que l'utilisateur a bien tapé quelque chose
    if not ip_adress:
        print("[-] Erreur : Vous n'avez saisi aucune adresse IP.")
    else:
        info_recup_IP = get_info_ip(ip_adress)

        if info_recup_IP:
            if "error" in info_recup_IP:
                print(f"[!] ERREUR : {info_recup_IP['error']}")
            else:
                print("\n[+] RÉSULTATS :")
                print(f" ├─ Adresse IP : {info_recup_IP.get('ip', 'Inconnue')}")
                print(f" ├─ ASN : {info_recup_IP.get('asn', 'Non renseigné')}")
                print(f" ├─ Opérateur : {info_recup_IP.get('org', 'Non renseigné')}")
                print(f" ├─ Pays : {info_recup_IP.get('country', 'Inconnu')}")
                print(f" └─ Ville : {info_recup_IP.get('city', 'Inconnue')}")
        else:
            print("[-] Aucune information récupérée.")
