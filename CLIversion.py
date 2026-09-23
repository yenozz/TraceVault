from Outils.mail_lookup import get_info_mail
from Outils.pseudo_lookup import get_info_pseudo
from Outils.pic_lookup import get_info_image
from Outils.telephone import analyser_telephone
from Outils.danger_score import calculer_score, afficher_rapport, generer_rapport_vulnerabilite
import os
import re
import sys
import time
import requests
from pystyle import Colorate, Colors
from colorama import init, Fore, Style
init(autoreset=True)

clear = lambda: os.system('cls')

_ANSI = re.compile(r'\033\[[0-9;]*m')

base_url = 'https://api.ipinfo.io/lite/'


# ─── Utilitaires ──────────────────────────────────────────────────────────────

def typewriter(text, delay=0.003):
    i = 0
    while i < len(text):
        match = _ANSI.match(text, i)
        if match:
            sys.stdout.write(match.group())
            sys.stdout.flush()
            i = match.end()
        else:
            sys.stdout.write(text[i])
            sys.stdout.flush()
            if text[i] not in (' ', '\n'):
                time.sleep(delay)
            i += 1


def proposer_rapport_vt(target: str):
    """Propose rapp VirusTotal fin d recherche"""
    print(Fore.YELLOW + "\n  >> Appuyez sur Entrée pour obtenir le rapport VirusTotal (ou tapez 'n' pour ignorer) : ", end="")
    try:
        choix = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if choix in ("n", "non", "no"):
        return
    print(Fore.CYAN + "\n[*] Analyse VirusTotal en cours...")
    score, niveau, raisons, type_cible, data = calculer_score(target)
    afficher_rapport(target, score, niveau, raisons, type_cible)
    print(Fore.YELLOW + "  >> Sauvegarder le rapport complet dans un fichier ? [o/N] : ", end="")
    try:
        choix2 = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if choix2 in ("o", "oui", "y", "yes"):
        chemin = generer_rapport_vulnerabilite(target, type_cible, score, niveau, raisons, data)
        print(Fore.GREEN + f"\n  [+] Rapport sauvegardé : {chemin}\n")



def prompt_retour1():
    while True:
        retour = input("\n00 - Revenir au menu principal\n> ")
        if retour == "00":
            clear()
            afficher_menu_principal()
            break
        else:
            print("[!] Choix invalide, veuillez saisir 00.")


def prompt_retour_chiffrement():
    while True:
        retour = input("\n00 - Revenir au menu de chiffrement\n> ")
        if retour == "00":
            clear()
            menu_chiffrement()
            break
        else:
            print("[!] Choix invalide, veuillez saisir 00.")


def prompt_retour2():
    while True:
        retour = input("\n00 - Revenir au menu principal\n> ")
        if retour == "00":
            clear()
            main_choice()
            break
        else:
            print("[!] Choix invalide, veuillez saisir 00.")

def get_info_ip(name=None):
    if name is None:
        name = input("Entrer l'ip a analyser : ")
    url = f"{base_url}{name}?token=6be41dd4d85adb"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        print(f"-------LOOKUP RESULT---------")
        for key, value in data.items():
            print(f"{key}: {value}")
        return data
    else:
        print("API Error.")
        return {"error": "API Error"}


def email_lookup():
    mail_cible = input("Entrez l'adresse e-mail à analyser : ")
    print(Fore.CYAN + "\n[*] Connexion aux services en cours...")
    print(Fore.CYAN + "[*] Les données arrivent, merci de patienter...\n")
    recup_mail = get_info_mail(mail_cible)
    if recup_mail and "error" not in recup_mail:
        total_trouve = recup_mail.get("total_trouve", 0)
        total_verifie = recup_mail.get("total_verifie", 0)
        print(f"\n-------| Résultats pour {recup_mail.get('email')} |-------")
        print(f" ├─ {total_trouve} trouvé(s) sur {total_verifie} services vérifiés\n")
        for compte in recup_mail.get("trouve_sur", []):
            print(Fore.GREEN + f" [+] {compte.get('name')}")
    else:
        print(f"[-] Erreur : {recup_mail.get('error', 'Aucune information trouvée.')}")
    proposer_rapport_vt(mail_cible)
    prompt_retour2()

# chiffremnt

def cesar_chiffrer(texte, decalage):
    resultat = []
    for c in texte:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            resultat.append(chr((ord(c) - base + decalage) % 26 + base))
        else:
            resultat.append(c)
    return ''.join(resultat)


def vigenere_chiffrer(texte, cle):
    cle = cle.upper()
    resultat = []
    idx = 0
    for c in texte:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            decalage = ord(cle[idx % len(cle)]) - ord('A')
            resultat.append(chr((ord(c) - base + decalage) % 26 + base))
            idx += 1
        else:
            resultat.append(c)
    return ''.join(resultat)


def vigenere_dechiffrer(texte, cle):
    cle = cle.upper()
    resultat = []
    idx = 0
    for c in texte:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            decalage = ord(cle[idx % len(cle)]) - ord('A')
            resultat.append(chr((ord(c) - base - decalage) % 26 + base))
            idx += 1
        else:
            resultat.append(c)
    return ''.join(resultat)


def menu_chiffrement():
    clear()
    print(Colorate.Horizontal(Colors.green_to_cyan, "\n─── Chiffrement / Déchiffrement ───\n"))
    print("1. Chiffrer   (César)")
    print("2. Déchiffrer (César)")
    print("3. Chiffrer   (Vigenère)")
    print("4. Déchiffrer (Vigenère)")
    print(Colorate.Horizontal(Colors.yellow_to_red, "00 - Revenir au menu principal"))
    choix = input("\nVotre choix : ").strip()

    if choix == "1":
        texte = input("Texte à chiffrer : ")
        try:
            decalage = int(input("Décalage (ex: 3) : "))
        except ValueError:
            print(Fore.RED + "[!] Décalage invalide.")
            return menu_chiffrement()
        print(Fore.GREEN + f"\n[+] Résultat : {cesar_chiffrer(texte, decalage)}\n")
        prompt_retour_chiffrement()

    elif choix == "2":
        texte = input("Texte à déchiffrer : ")
        try:
            decalage = int(input("Décalage utilisé lors du chiffrement (ex: 3) : "))
        except ValueError:
            print(Fore.RED + "[!] Décalage invalide.")
            return menu_chiffrement()
        print(Fore.GREEN + f"\n[+] Résultat : {cesar_chiffrer(texte, -decalage)}\n")
        prompt_retour_chiffrement()

    elif choix == "3":
        texte = input("Texte à chiffrer : ")
        cle = input("Clé Vigenère (lettres uniquement) : ")
        if not cle.isalpha():
            print(Fore.RED + "[!] La clé doit contenir uniquement des lettres.")
            return menu_chiffrement()
        print(Fore.GREEN + f"\n[+] Résultat : {vigenere_chiffrer(texte, cle)}\n")
        prompt_retour_chiffrement()

    elif choix == "4":
        texte = input("Texte à déchiffrer : ")
        cle = input("Clé Vigenère utilisée lors du chiffrement : ")
        if not cle.isalpha():
            print(Fore.RED + "[!] La clé doit contenir uniquement des lettres.")
            return menu_chiffrement()
        print(Fore.GREEN + f"\n[+] Résultat : {vigenere_dechiffrer(texte, cle)}\n")
        prompt_retour_chiffrement()

    elif choix == "00":
        clear()
        afficher_menu_principal()

    else:
        print(Fore.RED + "[!] Choix invalide.")
        menu_chiffrement()


# ─── Menus ────────────────────────────────────────────────────────────────────

def main_choice():
    print("\nQuelle est l'information dont vous disposez ?")
    print("1. Adresse IP")
    print("2. Adresse E-mail")
    print("3. Pseudonyme")
    print("4. Numéro de téléphone")
    print("5. Image")
    print(Colorate.Horizontal(Colors.yellow_to_red, "00 - Revenir au menu principal"))
    choice2 = input("\nSaisisez votre choix  : ")

    if choice2 == "1":
        clear()
        ip_saisi = input("Entrer l'ip a analyser : ")
        get_info_ip(ip_saisi)
        proposer_rapport_vt(ip_saisi)
        prompt_retour2()

    elif choice2 == "2":
        clear()
        email_lookup()

    elif choice2 == "3":
        clear()
        pseudo_cible = input("Entrez le nom d'utilisateur à analyser : ")
        print(Fore.CYAN + "\n[*] Connexion aux services en cours...")
        print(Fore.CYAN + "[*] Les données arrivent, merci de patienter...\n")
        recup_pseudo_unique = get_info_pseudo(pseudo_cible)
        if recup_pseudo_unique and "error" not in recup_pseudo_unique:
            print("\n-------| Résultats |-------")
            for compte in recup_pseudo_unique["trouve_sur"]:
                print(f" ├─ {compte['site']} : {compte['url']}")
        else:
            print(f"[-] Erreur : {recup_pseudo_unique.get('error', 'Aucune information trouvée.')}")
        prompt_retour2()

    elif choice2 == "4":
        clear()
        phone_cible = input("Entrez le numéro de téléphone à analyser : ")
        recup_phone_unique = analyser_telephone(phone_cible)
        if recup_phone_unique and "error" not in recup_phone_unique:
            print("\n-------| Résultats |-------")
            print(f"Numéro : {phone_cible}")
            print(f"Valide : {recup_phone_unique.get('valid', )}")
            print(f"Type : {recup_phone_unique.get('type')}")
            print(f"Pays: {recup_phone_unique.get('pays')}")
            print(f"Operateur : {recup_phone_unique.get('operateur')}")
            print(f"fuseau_horaire : {recup_phone_unique.get('fuseau_horaire')}")
            print(f"format_international : {recup_phone_unique.get('format_international')}")
            print(f"format national: {recup_phone_unique.get('format_national')}")
        else:
            print(f"[-] Erreur : {recup_phone_unique.get('error', 'Aucune information trouvée.')}")
        prompt_retour2()

    elif choice2 == "5":
        clear()
        chemin_image = input("Entrez le chemin local ou le nom de l'image (ex: photo.jpg) : ")
        recup_image = get_info_image(chemin_image)
        if recup_image and "error" not in recup_image:
            print("\n-------| Résultats |-------")
            for cle, valeur in recup_image.items():
                print(f" ├─ {cle} : {valeur}")
        else:
            print(f"[-] Erreur : {recup_image.get('error', 'Aucune information trouvée.')}")
        prompt_retour2()

    elif choice2 == "00":
        clear()
        afficher_menu_principal()

    else:
        print("\n[!] Choix invalide, veuillez réessayer.")
        main_choice()


def afficher_menu_principal():
    typewriter("""
 ▄▄▄█████▓ ██▀███   ▄▄▄       ▄████▄  ▓█████ ██▒   █▓ ▄▄▄       █    ██  ██▓  ▄▄▄█████▓
 ▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    ▒██▀ ▀█  ▓█   ▀▓██░   █▒▒████▄     ██  ▓██▒▓██▒  ▓  ██▒ ▓▒
 ▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  ▒▓█    ▄ ▒███   ▓██  █▒░▒██  ▀█▄  ▓██  ▒██░▒██░  ▒ ▓██░ ▒░
 ░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▒▓█  ▄  ▒██ █░░░██▄▄▄▄██ ▓▓█  ░██░▒██░  ░ ▓██▓ ░
   ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒▒ ▓███▀ ░░▒████▒  ▒▀█░   ▓█   ▓██▒▒▒█████▓ ░██████▒▒██▒ ░
   ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ░▒ ▒  ░░░ ▒░ ░  ░ ▐░   ▒▒   ▓▒█░░▒▓▒ ▒ ▒ ░ ▒░▓  ░▒ ░░
     ░      ░▒ ░ ▒░  ▒   ▒▒ ░  ░  ▒    ░ ░  ░  ░ ░░    ▒   ▒▒ ░░░▒░ ░ ░ ░ ░ ▒  ░  ░
   ░        ░░   ░   ░   ▒   ░           ░       ░░    ░   ▒    ░░░ ░ ░   ░ ░   ░
             ░           ░  ░░ ░         ░  ░     ░        ░  ░   ░         ░  ░
                             ░                   ░
""")
    print(Colorate.Horizontal(Colors.green_to_cyan, """\nDébuter votre recherche : \n1. Effectuer une recherche avec une information\n2. Effectuer une recherche avec plusieurs informations\n3. Chiffrement / Déchiffrement\n4. En savoir plus sur la RGPD\n00. Quitter TraceVault"""))
    choice1 = input("\nRentrez le numéro correspondant à votre choix : ")

    if choice1 == "1":
        clear()
        main_choice()

    elif choice1 == "2":
        clear()
        donnees_rapport_global = {"IP": None, "Email": None, "Pseudo": None, "Domaine": None}
        print("\n-------| Recherche Globale |-------")
        print("Remplissez les champs avec les informations dont vous disposez (Appuyez sur Entrée pour ignorer)\n")

        while True:
            ip_cible_globale = input("Saisissez une IP : ")
            valid1 = input(f"Votre recherche est bien '{ip_cible_globale}' ?\nConfirmer (o/n) ? ")
            if valid1 == "o":
                break
            print("[!] Saisie annulée, recommencez.\n")

        while True:
            mail_cible_globale = input("Saisissez une adresse e-mail : ")
            valid2 = input(f"Votre recherche est bien '{mail_cible_globale}' ?\nConfirmer (o/n) ? ")
            if valid2 == "o":
                break
            print("[!] Saisie annulée, recommencez.\n")

        while True:
            pseudo_cible_global = input("Saisissez un nom d'utilisateur : ")
            valid3 = input(f"Votre recherche est bien '{pseudo_cible_global}' ?\nConfirmer (o/n) ? ")
            if valid3 == "o":
                break
            print("[!] Saisie annulée, recommencez.\n")

        while True:
            phone_cible_global = input("Saisissez un numéro de téléphone (format international) : ")
            valid4 = input(f"Votre recherche est bien '{phone_cible_global}' ?\nConfirmer (o/n) ? ")
            if valid4 == "o":
                break
            print("[!] Saisie annulée, recommencez.\n")

        while True:
            pic_cible_global = input("Saisissez le chemin de l'image ou son nom : ")
            valid5 = input(f"Votre recherche est bien '{pic_cible_global}' ?\nConfirmer (o/n) ? ")
            if valid5 == "o":
                break
            print("[!] Saisie annulée, recommencez.\n")

        print(r"""

  /$$$$$$  /$$        /$$$$$$  /$$$$$$$   /$$$$$$  /$$
 /$$__  $$| $$       /$$__  $$| $$__  $$ /$$__  $$| $$
| $$  \__/| $$      | $$  \ $$| $$  \ $$| $$  \ $$| $$
| $$ /$$$$| $$      | $$  | $$| $$$$$$$ | $$$$$$$$| $$
| $$|_  $$| $$      | $$  | $$| $$__  $$| $$__  $$| $$
| $$  \ $$| $$      | $$  | $$| $$  \ $$| $$  | $$| $$
|  $$$$$$/| $$$$$$$$|  $$$$$$/| $$$$$$$/| $$  | $$| $$$$$$$$
 \______/ |________/ \______/ |_______/ |__/  |__/|________/

 /$$$$$$$  /$$$$$$$$  /$$$$$$  /$$$$$$$$  /$$$$$$  /$$$$$$$   /$$$$$$  /$$   /$$
| $$__  $$| $$_____/ /$$__  $$| $$_____/ /$$__  $$| $$__  $$ /$$__  $$| $$  | $$
| $$  \ $$| $$      | $$  \__/| $$      | $$  \ $$| $$  \ $$| $$  \__/| $$  | $$
| $$$$$$$/| $$$$$   |  $$$$$$ | $$$$$   | $$$$$$$$| $$$$$$$/| $$      | $$$$$$$$
| $$__  $$| $$__/    \____  $$| $$__/   | $$__  $$| $$__  $$| $$      | $$__  $$
| $$  \ $$| $$       /$$  \ $$| $$      | $$  | $$| $$  \ $$| $$    $$| $$  | $$
| $$  | $$| $$$$$$$$|  $$$$$$/| $$$$$$$$| $$  | $$| $$  | $$|  $$$$$$/| $$  | $$
|__/  |__/|________/ \______/ |________/|__/  |__/|__/  |__/ \______/ |__/  |__
                                                                                """)

        if ip_cible_globale:
            recup_ip_globale = get_info_ip(ip_cible_globale)
            if "error" not in recup_ip_globale:
                donnees_rapport_global["IP"] = recup_ip_globale

        if mail_cible_globale:
            print(Fore.CYAN + "\n[*] Connexion aux services en cours...")
            print(Fore.CYAN + "[*] Les données arrivent, merci de patienter...\n")
            recup_mail = get_info_mail(mail_cible_globale)
            if recup_mail and "error" not in recup_mail:
                total_trouve = recup_mail.get("total_trouve", 0)
                total_verifie = recup_mail.get("total_verifie", 0)
                print(f"\n-------| Résultats pour {recup_mail.get('email')} |-------")
                print(f" ├─ {total_trouve} trouvé(s) sur {total_verifie} services vérifiés\n")
                for compte in recup_mail.get("trouve_sur", []):
                    print(Fore.GREEN + f" [+] {compte.get('name')}")
            else:
                print(f"[-] Erreur : {recup_mail.get('error', 'Aucune information trouvée.')}")

        if pseudo_cible_global:
            print(Fore.CYAN + "\n[*] Connexion aux services en cours...")
            print(Fore.CYAN + "[*] Les données arrivent, merci de patienter...\n")
            recup_pseudo_globale = get_info_pseudo(pseudo_cible_global)

            if "error" not in recup_pseudo_globale:
                print("\n[+] Résultats Pseudo :")
                for compte in recup_pseudo_globale["trouve_sur"]:
                    print(f" ├─ {compte['site']} : {compte['url']}")
            else:
                print(f"[-] Erreur Pseudo : {recup_pseudo_globale.get('error')}")

        if phone_cible_global:
            recup_phone_global = analyser_telephone(phone_cible_global)
            if "error" not in recup_phone_global:
                print("\n[+] Résultats Téléphone :")
                print(f"Numéro : {phone_cible_global}")
                print(f"Valide : {recup_phone_global.get('valid', )}")
                print(f"Type : {recup_phone_global.get('type')}")
                print(f"Pays: {recup_phone_global.get('pays')}")
                print(f"Operateur : {recup_phone_global.get('operateur')}")
                print(f"fuseau_horaire : {recup_phone_global.get('fuseau_horaire')}")
                print(f"format_international : {recup_phone_global.get('format_international')}")
                print(f"format national: {recup_phone_global.get('format_national')}")
            else:
                print(f"[-] Erreur : {recup_phone_global.get('error', 'Aucune information trouvée.')}")

        if pic_cible_global:
            recup_pic_global = get_info_image(pic_cible_global)
            if recup_pic_global and "error" not in recup_pic_global:
                print("\n[+] Résultats Image :")
                for cle, valeur in recup_pic_global.items():
                    print(f" ├─ {cle} : {valeur}")
            else:
                print(f"[-] Erreur Image : {recup_pic_global.get('error', 'Aucune information trouvée.')}")

        if ip_cible_globale:
            proposer_rapport_vt(ip_cible_globale)
        if mail_cible_globale:
            proposer_rapport_vt(mail_cible_globale)

        prompt_retour1()

    elif choice1 == "3":
        menu_chiffrement()

    elif choice1 == "4":
        clear()
        print(Colorate.Horizontal(Colors.red_to_white, """
                         AVERTISSEMENT LEGAL
      ═════════════════════════════════════════════════════════════════

 TraceVault utilise exclusivement des sources publiques (OSINT passif).
 Aucune donnée n'est envoyée à des tiers ni stockée hors de votre machine.
 Les rapports sont chiffrés localement et accessibles par vous seul.

 Utilisation autorisée uniquement sur :
   • vos propres actifs numériques
   • des cibles pour lesquelles vous avez une autorisation explicite
   • des environnements de test (CTF, labs, domaines de démonstration)

 Toute utilisation à des fins de surveillance ou de collecte de données
 sans base légale est une infraction au RGPD (UE 2016/679) et au droit pénal.
 L'utilisateur est seul responsable du traitement effectué.

      ═════════════════════════════════════════════════════════════════"""))
        prompt_retour1()

    elif choice1 == "00":
        print(Fore.CYAN + "\nMerci d'avoir utilisé TraceVault. À bientôt !\n")

    else:
        print("\n[!] Votre choix n'est pas valide, veuillez réessayer.")
        afficher_menu_principal()


afficher_menu_principal()
