import phonenumbers
from phonenumbers import geocoder, carrier

def get_info_phone(phone):
    """
    Analyse un numéro de téléphone localement via la bibliothèque de Google.
    
    """
    # Nettoyage de base
    phone = phone.strip().replace(" ", "")
    
    # Sécurité OSINT : Si l'utilisateur tape un numéro français classique (ex: 0612345678)
    # on le convertit automatiquement au format international (+33612345678)
    if phone.startswith("0") and not phone.startswith("+"):
        phone = "+33" + phone[1:]
        
    if not phone.startswith("+"):
        return {"error": "Le numéro doit commencer par '+' suivi du code pays (ex: +336...)"}
    
    try:
        # Analyse (parsing) du numéro
        parsed_number = phonenumbers.parse(phone, None)
        
        # 1. Vérification de la validité réelle du numéro
        is_valid = phonenumbers.is_valid_number(parsed_number)
        if not is_valid:
            return {"error": "Le format semble correct mais ce numéro n'existe pas ou est invalide."}
            
        # 2. Localisation géographique (Pays / Région)
        pays = geocoder.description_for_number(parsed_number, "fr")
        
        # 3. Identification de l'opérateur d'origine (Carrier)
        operateur = carrier.name_for_number(parsed_number, "fr")
        
        return {
            "phone": phone,
            "valid": "Oui" if is_valid else "Non",
            "country": pays if pays else "Inconnu (International)",
            "carrier": operateur if operateur else "Opérateur inconnu ou virtuel (VoIP)"
        }
        
    except Exception as e:
        return {"error": f"Erreur lors du traitement du numéro : {str(e)}"}
