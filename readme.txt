============================================================
                        TRACEVAULT
          Outil OSINT de recherche et de chiffrement
============================================================


PRE-REQUIS
----------
- Windows 10 / 11
- Python 3.9 ou superieur
  Telechargement : https://www.python.org/downloads/
  /!\ Cochez bien "Add Python to PATH" lors de l'installation


INSTALLATION
------------
1. Assurez-vous que Python est installe et ajoute au PATH.

2. Double-cliquez sur "install.bat" pour installer
   automatiquement toutes les dependances.

   OU ouvrez un terminal dans le dossier et tapez :
       pip install requests colorama pystyle phonenumbers
       pip install httpx trio holehe Pillow pillow-heif

3. Une fois l'installation terminee, lancez le programme :
       python CLIversion.py


UTILISATION
-----------
Au lancement, le menu principal propose 4 options :

  1. Effectuer une recherche avec une information
     --> Recherche OSINT sur : IP, E-mail, Pseudo,
         Numero de telephone, ou Image (metadonnees EXIF).

  2. Effectuer une recherche avec plusieurs informations
     --> Recherche globale combinant plusieurs cibles
         en une seule session.

  3. Chiffrement / Dechiffrement
     --> Chiffrez ou dechiffrez du texte avec :
         - Cesar  : decalage alphabetique par un nombre
         - Vigenere : chiffrement par une cle textuelle

         Sous-menu disponible :
           1. Chiffrer   (Cesar)
           2. Dechiffrer (Cesar)
           3. Chiffrer   (Vigenere)
           4. Dechiffrer (Vigenere)

  4. En savoir plus sur la RGPD
     --> Rappel legal sur l'utilisation responsable
         de l'outil.

  00. Quitter TraceVault


NAVIGATION
----------
- Tapez le numero correspondant a votre choix et appuyez sur Entree.
- Dans tous les menus, "00" permet de revenir au menu precedent.


AVERTISSEMENT LEGAL
-------------------
TraceVault utilise exclusivement des sources publiques (OSINT passif).
Toute utilisation a des fins de surveillance ou de collecte de donnees
sans consentement est une infraction au RGPD (UE 2016/679).
L'utilisateur est seul responsable de l'usage qu'il fait de cet outil.


============================================================
