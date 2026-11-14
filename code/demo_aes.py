"""
Démo A1 — Modes AES et mauvais usages (Groupe 7, S3, 11/11/2026)

Usage :  python3 demo_aes.py [dossier_images]
  (par défaut les images sont écrites dans ../img)

Parties :
  1. Même image chiffrée en ECB puis en CBC  -> img/demo_original.png, demo_ecb.png, demo_cbc.png
  1 bis. Logo de l'ESP (img/esp_logo.jpg), brut et « plat » (6 couleurs), en ECB puis en CBC
                                             -> img/esp_{brut,plat}_{original,ecb,cbc}.png
  2. CTR avec un nonce réutilisé             -> Kiné lit un message sans la clé
  3. CTR sans intégrité (malléabilité)       -> Modou change 5000 en 9000 sans la clé
  4. GCM                                     -> la même modification est détectée

Tout se fait sur nos propres données : aucune appli réelle n'est attaquée.
"""
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image, ImageDraw, ImageFont

DOSSIER = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "img")
os.makedirs(DOSSIER, exist_ok=True)

BLEU, ORANGE, BLANC, VERT = (11, 60, 110), (224, 122, 31), (255, 255, 255), (46, 125, 79)


def titre(texte):
    print("\n" + "=" * 64 + f"\n {texte}\n" + "=" * 64)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# 1. ECB contre CBC sur une image
# ---------------------------------------------------------------------------
def fabriquer_image(l=480, h=270) -> Image.Image:
    """Image à aplats de couleur (comme un logo) : idéale pour voir l'effet ECB."""
    img = Image.new("RGB", (l, h), BLANC)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, l, 40], fill=BLEU)                      # bandeau
    d.rounded_rectangle([40, 70, 170, 250], 18, fill=BLEU)     # téléphone
    d.rectangle([55, 90, 155, 210], fill=BLANC)                # écran
    d.ellipse([92, 220, 118, 244], fill=BLANC)                 # bouton
    d.ellipse([230, 80, 400, 250], fill=ORANGE)                # pièce
    d.ellipse([265, 115, 365, 215], fill=BLANC)
    try:
        police = ImageFont.truetype("DejaVuSans-Bold.ttf", 46)
    except OSError:
        police = ImageFont.load_default()
    d.text((278, 135), "A1", fill=VERT, font=police)
    return img


def chiffrer_pixels(pixels: bytes, mode, cle: bytes) -> bytes:
    enc = Cipher(algorithms.AES(cle), mode).encryptor()
    reste = len(pixels) % 16
    bourrage = b"\x00" * ((16 - reste) % 16)                   # on bourre pour avoir des blocs entiers
    c = enc.update(pixels + bourrage) + enc.finalize()
    return c[: len(pixels)]                                    # on garde la taille de l'image


def partie_images(cle):
    titre("1. La même image chiffrée en ECB puis en CBC")
    img = fabriquer_image()
    pixels = img.tobytes()
    ecb = chiffrer_pixels(pixels, modes.ECB(), cle)
    cbc = chiffrer_pixels(pixels, modes.CBC(os.urandom(16)), cle)
    for nom, data in [("demo_original.png", pixels), ("demo_ecb.png", ecb), ("demo_cbc.png", cbc)]:
        Image.frombytes("RGB", img.size, data).save(os.path.join(DOSSIER, nom))
        print(f"  écrit : {os.path.join(DOSSIER, nom)}")
    print("  -> ECB : blocs identiques = chiffrés identiques, le dessin reste visible.")
    print("  -> CBC : chaque bloc dépend du précédent et de l'IV, on ne voit que du bruit.")


# ---------------------------------------------------------------------------
# 2. CTR : nonce réutilisé
# ---------------------------------------------------------------------------
def ctr(cle, nonce, data):
    enc = Cipher(algorithms.AES(cle), modes.CTR(nonce)).encryptor()
    return enc.update(data) + enc.finalize()


def partie_nonce(cle):
    titre("2. CTR : l'appli réutilise le MÊME nonce pour deux messages")
    nonce = b"\x00" * 16                                       # erreur : nonce fixe
    m1 = b"VIRE 5000 FCFA A MOUSSA ; PIN=0000"                  # message connu de Kiné (format standard)
    m2 = b"VIRE 7500 FCFA A AWA    ; PIN=4821"                  # message secret
    c1, c2 = ctr(cle, nonce, m1), ctr(cle, nonce, m2)
    print(f"  c1 = {c1.hex()[:48]}...")
    print(f"  c2 = {c2.hex()[:48]}...")
    masque = xor(c1, m1)                                       # z = c1 XOR m1
    retrouve = xor(c2, masque)                                 # m2 = c2 XOR z
    print(f"  Kiné connaît m1, calcule z = c1 xor m1, puis c2 xor z :")
    print(f"  m2 retrouvé SANS la clé : {retrouve.decode()}")


# ---------------------------------------------------------------------------
# 3. CTR sans intégrité : malléabilité
# ---------------------------------------------------------------------------
def partie_malleabilite(cle):
    titre("3. CTR sans intégrité : Modou modifie le montant sans la clé")
    nonce = os.urandom(16)
    m = b"VIRE 5000 FCFA A MOUSSA"
    c = bytearray(ctr(cle, nonce, m))
    pos = m.index(b"5")
    c[pos] ^= ord("5") ^ ord("9")                              # delta = '5' xor '9'
    print(f"  message envoyé : {m.decode()}")
    print(f"  Modou inverse quelques bits du chiffré (position {pos}, delta = '5' xor '9')")
    print(f"  la banque déchiffre : {ctr(cle, nonce, bytes(c)).decode()}   <- personne ne s'en rend compte")


# ---------------------------------------------------------------------------
# 4. GCM : la même attaque est détectée
# ---------------------------------------------------------------------------
def partie_gcm():
    titre("4. Même attaque contre AES-GCM (chiffrement authentifié)")
    cle = AESGCM.generate_key(bit_length=128)
    gcm, nonce = AESGCM(cle), os.urandom(12)                   # nonce de 96 bits, unique
    m = b"VIRE 5000 FCFA A MOUSSA"
    c = bytearray(gcm.encrypt(nonce, m, None))                 # chiffré + tag de 16 octets
    c[m.index(b"5")] ^= ord("5") ^ ord("9")
    try:
        gcm.decrypt(nonce, bytes(c), None)
        print("  (inattendu) message accepté")
    except InvalidTag:
        print("  la banque vérifie le tag : InvalidTag -> message REJETÉ. Modification détectée.")


def proportion_repetes(data):
    bs = [data[i:i + 16] for i in range(0, len(data) - len(data) % 16, 16)]
    compte = {}
    for b in bs:
        compte[b] = compte.get(b, 0) + 1
    return sum(n for n in compte.values() if n > 1) / len(bs)


def partie_logo_esp(cle):
    """Démo demandée par la fiche A1 : le logo de l'ESP chiffré en ECB puis en CBC."""
    chemin = os.path.join(DOSSIER, "esp_logo.jpg")
    if not os.path.exists(chemin):
        print(f"\n(logo ESP absent : {chemin})")
        return
    titre("1 bis. Le logo de l'ESP chiffré en ECB puis en CBC")
    photo = Image.open(chemin).convert("RGB").resize((640, 360))
    logo = photo.quantize(colors=6, method=Image.Quantize.MEDIANCUT).convert("RGB")   # « logo plat »
    for nom, img in [("brut", photo), ("plat", logo)]:
        px = img.tobytes()
        ecb = chiffrer_pixels(px, modes.ECB(), cle)
        cbc = chiffrer_pixels(px, modes.CBC(os.urandom(16)), cle)
        img.save(os.path.join(DOSSIER, f"esp_{nom}_original.png"))
        Image.frombytes("RGB", img.size, ecb).save(os.path.join(DOSSIER, f"esp_{nom}_ecb.png"))
        Image.frombytes("RGB", img.size, cbc).save(os.path.join(DOSSIER, f"esp_{nom}_cbc.png"))
        print(f"  logo {nom:5s} : {100 * proportion_repetes(px):5.1f} % de blocs répétés "
              f"-> ECB {100 * proportion_repetes(ecb):5.1f} %, CBC {100 * proportion_repetes(cbc):5.1f} %")
    print("  -> ECB fuit d'autant plus que les données se répètent : logo plat très visible, photo à peine.")


if __name__ == "__main__":
    cle = os.urandom(16)                                       # AES-128, clé aléatoire
    partie_images(cle)
    partie_logo_esp(cle)
    partie_nonce(cle)
    partie_malleabilite(cle)
    partie_gcm()
    print()
