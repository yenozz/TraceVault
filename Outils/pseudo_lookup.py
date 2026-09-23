import requests

plateformes = {
        # --- Plateformes fiables (répondent bien aux 404) ---
        "GitHub": "https://github.com/{}",
        "Reddit": "https://www.reddit.com/user/{}",
        "HackTheBox": "https://app.hackthebox.com/users/{}",
        "Steam": "https://steamcommunity.com/id/{}",
        "Twitch": "https://www.twitch.tv/{}",
        "Pinterest": "https://www.pinterest.com/{}/",
        "Spotify": "https://open.spotify.com/user/{}",
        "Patreon": "https://www.patreon.com/{}",
        "Vimeo": "https://vimeo.com/{}",
        "SoundCloud": "https://soundcloud.com/{}",
        "Linktree": "https://linktr.ee/{}",
        "Medium": "https://medium.com/@{}",
        
        # --- Réseaux sociaux capricieux (Anti-bots fréquents) ---
        "Instagram": "https://www.instagram.com/{}/",
        "TikTok": "https://www.tiktok.com/@{}",
        "Facebook": "https://www.facebook.com/{}",
        "Snapchat": "https://www.snapchat.com/add/{}",
        "X (Twitter)": "https://twitter.com/{}"
    }

def get_info_pseudo(pseudo):
    # On se déguise en navigateur web classique pour éviter d'être bloqué instantanément
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    resultats = {"pseudo_recherche": pseudo, "trouve_sur": []}

    for nom_site, url_base in plateformes.items():
        url_a_tester = url_base.format(pseudo)
        
        try:
            # On ajoute le headers pour simuler un vrai navigateur
            response = requests.get(url_a_tester, headers=headers, timeout=5)
            
            # Si le serveur répond 200 OK, la page semble exister
            if response.status_code == 200:
                resultats["trouve_sur"].append({"site": nom_site, "url": url_a_tester})
            
            # Gestion visuelle des blocages (optionnelle mais utile pour le debug)
            elif response.status_code == 403:
                print(f"[!] {nom_site} a bloqué la requête (Anti-bot).")
                
        except requests.exceptions.RequestException:
            print(f"[-] Erreur de connexion avec {nom_site}")

    if not resultats["trouve_sur"]:
        return {"error": "Aucun profil trouvé avec ce pseudonyme sur nos sources."}
        
    return resultats

# --- Zone de test ---
if __name__ == "__main__":
    pseudo_cible = input("Entrez le pseudonyme à rechercher : ")
    if pseudo_cible:
        infos = get_info_pseudo(pseudo_cible)
        if "error" in infos:
            print(f"\n[-] {infos['error']}")
        else:
            print("\n-------| Bilan des Recherches |-------")
            for compte in infos["trouve_sur"]:
                print(f" ├─ {compte['site']} : {compte['url']}")
