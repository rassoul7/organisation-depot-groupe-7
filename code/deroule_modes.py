"""
Exemple déroulé A1 : le même ordre de virement chiffré avec TOUS les modes.

Message de 3 blocs de 16 octets, dont les blocs 2 et 3 sont identiques.
Clé, IV et nonce de DÉMONSTRATION, fixes et publics : tout le monde peut refaire le calcul.
(En vrai, l'IV et le nonce doivent être tirés au hasard à chaque message.)

Usage : python3 deroule_modes.py
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:  # depuis cryptography 46, CFB et OFB sont rangés dans « decrepit » (obsolètes)
    from cryptography.hazmat.decrepit.ciphers.modes import CFB, OFB
except ImportError:
    CFB, OFB = modes.CFB, modes.OFB

CLE = bytes.fromhex("000102030405060708090a0b0c0d0e0f")      # clé de démonstration (FIPS 197)
IV = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")       # IV / compteur initial de démonstration
NONCE12 = IV[:12]                                             # nonce GCM de 96 bits
M = b"DEST:MOUSSA_____" + b"MONTANT:5000FCFA" + b"MONTANT:5000FCFA"


def chiffrer(nom):
    if nom == "GCM":
        sortie = AESGCM(CLE).encrypt(NONCE12, M, None)
        return sortie[:-16], sortie[-16:]
    mode = {"ECB": modes.ECB(), "CBC": modes.CBC(IV), "CFB": CFB(IV),
            "OFB": OFB(IV), "CTR": modes.CTR(IV)}[nom]
    e = Cipher(algorithms.AES(CLE), mode).encryptor()
    return e.update(M) + e.finalize(), None


def court(b):
    return b.hex()[:8] + "…"


print("Message : " + " | ".join(M[i:i + 16].decode() for i in range(0, 48, 16)))
print(f"Clé {CLE.hex()}   IV/compteur {IV.hex()}   nonce GCM {NONCE12.hex()}\n")
print(f"{'mode':5s} {'c1':12s} {'c2':12s} {'c3':12s} {'c2 = c3 ?':10s} tag (GCM)")
for nom in ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM"]:
    c, tag = chiffrer(nom)
    b = [c[i:i + 16] for i in range(0, 48, 16)]
    egal = "OUI (fuite)" if b[1] == b[2] else "non"
    print(f"{nom:5s} {court(b[0]):12s} {court(b[1]):12s} {court(b[2]):12s} {egal:10s} {court(tag) if tag else '-'}")
