import re
import sys
import base64
import datetime
import os
import requests

API_KEY = "5767f1d382111e878d20139a2f253acd096d5a34a9c85b396431679f24164d1a"

HEADERS = {
    "accept": "application/json",
    "x-apikey": API_KEY,
}

# ─── Détection du type de cible ────────────────────────────────────────────────

def detect_type(target: str) -> str:
    target = target.strip()
    # IPv4
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return "ip"
    # Hash MD5 / SHA1 / SHA256
    if re.match(r"^[a-fA-F0-9]{32}$", target):
        return "hash"
    if re.match(r"^[a-fA-F0-9]{40}$", target):
        return "hash"
    if re.match(r"^[a-fA-F0-9]{64}$", target):
        return "hash"
    # Email → on vérifie le domaine
    if re.match(r"^[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}$", target):
        return "email"
    # URL
    if re.match(r"^https?://", target):
        return "url"
    # Domain par défaut
    return "domain"


# ─── Requêtes VirusTotal ────────────────────────────────────────────────────────

def _vt_get(path: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/{path}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 401:
            return {"error": "Clé API invalide."}
        if r.status_code == 404:
            return {"error": "Ressource introuvable dans VirusTotal."}
        if r.status_code == 429:
            return {"error": "Quota API VirusTotal dépassé."}
        return {"error": f"Erreur HTTP {r.status_code}."}
    except requests.exceptions.RequestException as e:
        return {"error": f"Erreur réseau : {e}"}


def query_ip(ip: str) -> dict:
    return _vt_get(f"ip_addresses/{ip}")


def query_domain(domain: str) -> dict:
    return _vt_get(f"domains/{domain}")


def query_url(url: str) -> dict:
    # VirusTotal attend un identifiant base64url sans padding
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    return _vt_get(f"urls/{url_id}")


def query_hash(file_hash: str) -> dict:
    return _vt_get(f"files/{file_hash}")


def query_email(email: str) -> dict:
    domain = email.split("@", 1)[1]
    data = query_domain(domain)
    if "error" not in data:
        data["_email_domain"] = domain
    return data


# ─── Calcul du score 0-100 ─────────────────────────────────────────────────────

def _score_from_stats(attrs: dict) -> tuple[int, list[str]]:
    """Calcule un score partiel (0-100) et liste les raisons à partir des attributs VT."""
    raisons = []
    score = 0

    stats = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious",  0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless",   0)
    undetected = stats.get("undetected", 0)
    timeout    = stats.get("timeout",    0)
    total = malicious + suspicious + harmless + undetected + timeout

    if total > 0:
        mal_ratio  = malicious  / total
        susp_ratio = suspicious / total
        # Pondération : malicieux pèse 90, suspect pèse 40
        score = int(min(100, mal_ratio * 90 + susp_ratio * 40))
        if malicious > 0:
            raisons.append(f"Détecté MALVEILLANT par {malicious}/{total} moteurs.")
        if suspicious > 0:
            raisons.append(f"Marqué SUSPECT par {suspicious}/{total} moteurs.")

    # Réputation VT (-100 à +100, valeurs négatives = mauvaise réputation)
    reputation = attrs.get("reputation")
    if reputation is not None and reputation < 0:
        rep_penalty = int(min(30, abs(reputation) / 100 * 30))
        score = min(100, score + rep_penalty)
        raisons.append(f"Réputation VirusTotal négative : {reputation}.")

    # Catégories malveillantes connues (pour les domaines/IPs)
    categories = attrs.get("categories", {})
    bad_cats = {"malware", "phishing", "spam", "botnet", "malicious"}
    found_bad = [c for c in categories.values() if c.lower() in bad_cats]
    if found_bad:
        score = min(100, score + 20)
        raisons.append(f"Catégorie(s) dangereuse(s) : {', '.join(set(found_bad))}.")

    return score, raisons


def calculer_score(target: str) -> tuple[int, str, list[str], str, dict]:
    """Retourne (score, niveau, raisons, type_detecte, data_brute)."""
    target = target.strip()
    type_cible = detect_type(target)

    dispatch = {
        "ip":     query_ip,
        "domain": query_domain,
        "url":    query_url,
        "hash":   query_hash,
        "email":  query_email,
    }

    data = dispatch[type_cible](target)

    if "error" in data:
        return 0, "Inconnu", [f"Erreur : {data['error']}"], type_cible, {}

    attrs = data.get("data", {}).get("attributes", {})
    score, raisons = _score_from_stats(attrs)

    if type_cible == "email":
        raisons = [f"[Domaine @{data.get('_email_domain', '')}] " + r for r in raisons]

    if score == 0:
        niveau = "Aucun risque detecte"
    elif score <= 25:
        niveau = "Risque faible"
    elif score <= 50:
        niveau = "Risque modere"
    elif score <= 75:
        niveau = "Risque eleve"
    else:
        niveau = "RISQUE CRITIQUE"

    return score, niveau, raisons, type_cible, data


# ─── Rapport de vulnérabilité détaillé ────────────────────────────────────────

def _fmt(label: str, value) -> str:
    return f"  {label:<30}: {value}\n"


def _section(titre: str) -> str:
    return f"\n{'─' * 55}\n  {titre}\n{'─' * 55}\n"


def _build_rapport_ip(attrs: dict) -> str:
    out = _section("INFORMATIONS RESEAU")
    out += _fmt("Pays", attrs.get("country", "N/A"))
    out += _fmt("Continent", attrs.get("continent", "N/A"))
    out += _fmt("ASN", attrs.get("asn", "N/A"))
    out += _fmt("Proprietaire AS", attrs.get("as_owner", "N/A"))
    out += _fmt("Plage reseau", attrs.get("network", "N/A"))
    out += _fmt("Reputation VT", attrs.get("reputation", "N/A"))
    tags = attrs.get("tags", [])
    if tags:
        out += _fmt("Tags", ", ".join(tags))
    votes = attrs.get("total_votes", {})
    if votes:
        out += _fmt("Votes (malicious)", votes.get("malicious", 0))
        out += _fmt("Votes (harmless)", votes.get("harmless", 0))
    return out


def _build_rapport_domain(attrs: dict) -> str:
    out = _section("INFORMATIONS DOMAINE")
    out += _fmt("Registrar", attrs.get("registrar", "N/A"))
    for champ in ("creation_date", "last_update_date", "expiration_date"):
        val = attrs.get(champ)
        if val:
            try:
                out += _fmt(champ, datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc).strftime("%Y-%m-%d"))
            except Exception:
                out += _fmt(champ, val)
    out += _fmt("Reputation VT", attrs.get("reputation", "N/A"))
    cats = attrs.get("categories", {})
    if cats:
        out += _fmt("Categories", ", ".join(set(cats.values())))
    tags = attrs.get("tags", [])
    if tags:
        out += _fmt("Tags", ", ".join(tags))
    votes = attrs.get("total_votes", {})
    if votes:
        out += _fmt("Votes (malicious)", votes.get("malicious", 0))
        out += _fmt("Votes (harmless)", votes.get("harmless", 0))
    return out


def _build_rapport_url(attrs: dict) -> str:
    out = _section("INFORMATIONS URL")
    out += _fmt("URL finale", attrs.get("last_final_url", attrs.get("url", "N/A")))
    out += _fmt("Titre page", attrs.get("title", "N/A"))
    chain = attrs.get("redirection_chain", [])
    if chain:
        out += _section("CHAINE DE REDIRECTIONS")
        for i, u in enumerate(chain, 1):
            out += f"  {i}. {u}\n"
    cats = attrs.get("categories", {})
    if cats:
        out += _fmt("Categories", ", ".join(set(cats.values())))
    return out


def _build_rapport_hash(attrs: dict) -> str:
    out = _section("INFORMATIONS FICHIER")
    out += _fmt("Nom", attrs.get("meaningful_name", attrs.get("name", "N/A")))
    out += _fmt("Type", attrs.get("type_description", attrs.get("type_tag", "N/A")))
    size = attrs.get("size")
    if size:
        out += _fmt("Taille", f"{size:,} octets")
    out += _fmt("MD5", attrs.get("md5", "N/A"))
    out += _fmt("SHA1", attrs.get("sha1", "N/A"))
    out += _fmt("SHA256", attrs.get("sha256", "N/A"))
    sig = attrs.get("signature_info", {})
    if sig:
        out += _fmt("Signature", sig.get("description", "N/A"))
        out += _fmt("Editeur", sig.get("publisher", "N/A"))
    tags = attrs.get("tags", [])
    if tags:
        out += _fmt("Tags", ", ".join(tags))
    return out


def _build_moteurs(attrs: dict) -> str:
    results = attrs.get("last_analysis_results", {})
    if not results:
        return ""
    positifs = {
        nom: r for nom, r in results.items()
        if r.get("category") in ("malicious", "suspicious")
    }
    if not positifs:
        return _section("MOTEURS") + "  Aucune detection positive.\n"
    out = _section(f"DETECTIONS POSITIVES ({len(positifs)} moteur(s))")
    for nom, r in positifs.items():
        cat = r.get("category", "?").upper()
        result_name = r.get("result") or "—"
        out += f"  [{cat:<10}] {nom:<25} -> {result_name}\n"
    return out


def generer_rapport_vulnerabilite(target: str, type_cible: str, score: int, niveau: str,
                                   raisons: list[str], data: dict) -> str:
    """Génère et sauvegarde un rapport détaillé. Retourne le chemin du fichier."""
    attrs = data.get("data", {}).get("attributes", {})
    now = datetime.datetime.now()
    horodatage = now.strftime("%Y-%m-%d %H:%M:%S")
    slug = re.sub(r"[^\w.-]", "_", target)[:40]
    nom_fichier = f"rapport_{slug}_{now.strftime('%Y%m%d_%H%M%S')}.txt"
    dossier = os.path.join(os.path.expanduser("~"), "Downloads")
    chemin = os.path.join(dossier, nom_fichier)

    contenu = ""
    contenu += "=" * 55 + "\n"
    contenu += "  RAPPORT DE VULNERABILITE VIRUSTOTAL\n"
    contenu += "=" * 55 + "\n"
    contenu += _fmt("Date d'analyse", horodatage)
    contenu += _fmt("Cible", target)
    contenu += _fmt("Type", type_cible.upper())
    contenu += _fmt("Score de risque", f"{score}/100")
    contenu += _fmt("Niveau", niveau)

    if raisons:
        contenu += _section("RESUME DES RISQUES")
        for r in raisons:
            contenu += f"  - {r}\n"

    stats = attrs.get("last_analysis_stats", {})
    if stats:
        contenu += _section("STATISTIQUES D'ANALYSE")
        for k, v in stats.items():
            contenu += _fmt(k.capitalize(), v)

    builders = {
        "ip":     _build_rapport_ip,
        "domain": _build_rapport_domain,
        "email":  _build_rapport_domain,
        "url":    _build_rapport_url,
        "hash":   _build_rapport_hash,
    }
    if type_cible in builders:
        contenu += builders[type_cible](attrs)

    contenu += _build_moteurs(attrs)
    contenu += "\n" + "=" * 55 + "\n"

    with open(chemin, "w", encoding="utf-8") as f:
        f.write(contenu)

    return chemin


# ─── Affichage ─────────────────────────────────────────────────────────────────

def _barre(score: int, largeur: int = 40) -> str:
    filled = int(score / 100 * largeur)
    return "[" + "#" * filled + "-" * (largeur - filled) + "]"


def afficher_rapport(target: str, score: int, niveau: str, raisons: list[str], type_cible: str):
    print("\n" + "=" * 55)
    print(f"  RAPPORT DE RISQUE VIRUSTOTAL")
    print("=" * 55)
    print(f"  Cible    : {target}")
    print(f"  Type     : {type_cible.upper()}")
    print(f"  Score    : {score}/100  {_barre(score)}")
    print(f"  Niveau   : {niveau}")
    print("-" * 55)
    if raisons:
        print("  Details :")
        for r in raisons:
            print(f"    - {r}")
    else:
        print("  Aucune anomalie detectee.")
    print("=" * 55 + "\n")


# ─── Point d'entrée ────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1:
        targets = sys.argv[1:]
    else:
        print("=== Analyseur de risque VirusTotal ===")
        print("Entrez une ou plusieurs cibles (IP, domaine, email, URL, hash).")
        print("Separez plusieurs cibles par des virgules, ou tapez 'quitter'.\n")
        raw = input("Cible(s) : ").strip()
        if raw.lower() in ("quitter", "exit", "q"):
            return
        targets = [t.strip() for t in raw.split(",") if t.strip()]

    for target in targets:
        score, niveau, raisons, type_cible, data = calculer_score(target)
        afficher_rapport(target, score, niveau, raisons, type_cible)

        try:
            choix = input("  >> Obtenir le rapport de vulnerabilite complet ? [o/N] : ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choix = "n"

        if choix in ("o", "oui", "y", "yes"):
            chemin = generer_rapport_vulnerabilite(target, type_cible, score, niveau, raisons, data)
            print(f"\n  Rapport sauvegarde : {chemin}\n")
        else:
            print()


if __name__ == "__main__":
    main()
