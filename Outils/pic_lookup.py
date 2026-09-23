# Fichier : Outils/pic_lookup.py
from PIL import Image
from PIL.ExifTags import TAGS
import pillow_heif

# Enregistre le décodeur HEIF/HEIC pour Pillow
pillow_heif.register_heif_opener()

def get_info_image(chemin_image):
    """
    Extrait les métadonnées EXIF d'une image locale (JPG, PNG, HEIC) pour l'analyse OSINT.
    Version corrigée et robuste sans méthode privée (_getexif).
    """
    try:
        image = Image.open(chemin_image)
        
        # Sécurité : On utilise getexif() sans underscore, compatible avec TOUS les formats
        exif_data = image.getexif()
        
        if not exif_data:
            return {"error": "Aucune métadonnée EXIF trouvée. L'image a probablement été nettoyée."}
        
        metadonnees = {}
        for tag_id, v in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            
            # On ignore les gros blocs de données brutes illisibles pour l'affichage CLI
            if tag_name not in ["MakerNote", "UserComment", "ComponentsConfiguration"]:
                # Si la valeur est en bytes (octets), on la décode proprement en texte
                if isinstance(v, bytes):
                    try:
                        v = v.decode('utf-8', errors='ignore').strip()
                    except:
                        pass
                metadonnees[str(tag_name)] = v
                
        return metadonnees

    except FileNotFoundError:
        return {"error": "Le fichier image spécifié est introuvable."}
    except Exception as e:
        return {"error": f"Impossible de lire l'image : {str(e)}"}
