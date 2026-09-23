import phonenumbers
from phonenumbers import geocoder, carrier
from phonenumbers import timezone as tz

_TYPES = {
    phonenumbers.PhoneNumberType.MOBILE:              "Telephone Mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE:          "Telephone Fixe",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE:"Telephone Fixe ou Mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE:           "Numéro vert",
    phonenumbers.PhoneNumberType.PREMIUM_RATE:        "Numero Surtaxé",
    phonenumbers.PhoneNumberType.VOIP:                "Numero VoIP()",
    phonenumbers.PhoneNumberType.PAGER:               "Numero Pager",
    phonenumbers.PhoneNumberType.SHARED_COST:         "Coût partagé",
}

def analyser_telephone(numero):
    try:
        parsed = phonenumbers.parse(numero, None)
    except Exception:
        return {"valide": False}

    return {
        "valide":                phonenumbers.is_valid_number(parsed),
        "type":                  _TYPES.get(phonenumbers.number_type(parsed), "Inconnu"),
        "pays":                  geocoder.description_for_number(parsed, "fr") or "Inconnu",
        "operateur":             carrier.name_for_number(parsed, "fr") or "Inconnu",
        "fuseau_horaire":        list(tz.time_zones_for_number(parsed)),
        "format_international":  phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "format_national":       phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
    }
