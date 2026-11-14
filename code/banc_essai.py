"""
Banc d'essai A1 — Modes AES : mesurer les mauvais usages (Groupe 7, ESP-UCAD / LITA)

Usage :  python3 banc_essai.py [--rapide]
Sorties : resultats/resultats.json et resultats/resultats.md (dans le dossier du script)

Expériences (toutes sur des données synthétiques, aucune appli réelle n'est attaquée) :
  E1  Jeu IND-CPA programmé : avantage mesuré de l'adversaire pour 9 configurations
  E2  Fuite ECB : proportion de blocs chiffrés répétés (image, journal de transactions)
  E3  Modification d'un bit : effet sur le clair et détection, par mode
  E4  Attaque par oracle de remplissage sur CBC (Vaudenay 2002) : déchiffrement sans la clé
  E5  Nonce réutilisé en CTR et en GCM : récupération d'un message sans la clé
  E6  Débit (Mo/s) : ECB, CBC, CTR, GCM, ChaCha20-Poly1305
"""
import json
import os
import platform
import random
import statistics
import sys
import time

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

RAPIDE = "--rapide" in sys.argv
GRAINE = 20261111                         # graine fixe : les tirages « public » sont reproductibles
rng = random.Random(GRAINE)


def alea(n):
    # tirages pseudo-aléatoires mais reproductibles : acceptable ici car toutes les données sont synthétiques
    return rng.randbytes(n)
ICI = os.path.dirname(os.path.abspath(__file__))
SORTIE = os.path.join(ICI, "resultats")
os.makedirs(SORTIE, exist_ok=True)
R = {"meta": {}, "E1": [], "E2": [], "E3": [], "E4": {}, "E5": {}, "E6": []}


def titre(t):
    print("\n" + "=" * 70 + f"\n {t}\n" + "=" * 70)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def blocs(data, n=16):
    return [data[i:i + n] for i in range(0, len(data), n)]


def aes(cle, mode, data, dec=False):
    c = Cipher(algorithms.AES(cle), mode)
    o = c.decryptor() if dec else c.encryptor()
    return o.update(data) + o.finalize()


# ===========================================================================
# E1 — Jeu IND-CPA
# ===========================================================================
class Schema:
    """Un schéma de chiffrement = une configuration (mode + gestion de l'IV/nonce)."""

    def __init__(self, nom, cle):
        self.nom, self.cle, self.compteur = nom, cle, 0

    def iv_suivant(self):
        return (1000 + self.compteur).to_bytes(16, "big")   # IV prévisible : un compteur

    def chiffrer(self, m):
        k, n = self.cle, self.nom
        if n == "ECB":
            return b"", aes(k, modes.ECB(), m)
        if n == "CBC, IV fixe":
            iv = b"\x00" * 16
            return iv, aes(k, modes.CBC(iv), m)
        if n == "CBC, IV prévisible (compteur)":
            iv = self.iv_suivant(); self.compteur += 1
            return iv, aes(k, modes.CBC(iv), m)
        if n == "CBC, IV aléatoire":
            iv = alea(16)
            return iv, aes(k, modes.CBC(iv), m)
        if n == "CTR, nonce fixe":
            iv = b"\x00" * 16
            return iv, aes(k, modes.CTR(iv), m)
        if n == "CTR, nonce aléatoire":
            iv = alea(16)
            return iv, aes(k, modes.CTR(iv), m)
        if n == "GCM, nonce fixe":
            iv = b"\x00" * 12
            return iv, AESGCM(k).encrypt(iv, m, None)
        if n == "GCM, nonce aléatoire":
            iv = alea(12)
            return iv, AESGCM(k).encrypt(iv, m, None)
        if n == "ChaCha20-Poly1305, nonce aléatoire":
            iv = alea(12)
            return iv, ChaCha20Poly1305(k + k).encrypt(iv, m, None)
        raise ValueError(n)


def une_partie(nom):
    """Une partie du jeu IND-CPA. Renvoie True si l'adversaire gagne."""
    s = Schema(nom, alea(16))
    m0 = alea(16)
    # 1) l'adversaire utilise l'oracle de chiffrement sur m0
    iv_vu, c_vu = s.chiffrer(m0)
    # 2) il choisit les deux messages du défi
    if nom == "CBC, IV prévisible (compteur)":
        iv_prochain = s.iv_suivant()                       # il devine le prochain IV
        defi0 = xor(xor(m0, iv_vu), iv_prochain)           # astuce de BEAST : même entrée pour E_K
    else:
        defi0 = m0
    defi1 = alea(16)
    # 3) le challengeur tire b et chiffre m_b
    b = rng.randrange(2)
    _, c_etoile = s.chiffrer(defi0 if b == 0 else defi1)
    # 4) l'adversaire devine : « même chiffré que tout à l'heure => b = 0 »
    b_devine = 0 if c_etoile[:16] == c_vu[:16] else 1
    return b_devine == b


def E1(n_parties):
    titre(f"E1 — Jeu IND-CPA : {n_parties} parties par configuration")
    configs = ["ECB", "CBC, IV fixe", "CBC, IV prévisible (compteur)", "CBC, IV aléatoire",
               "CTR, nonce fixe", "CTR, nonce aléatoire", "GCM, nonce fixe", "GCM, nonce aléatoire",
               "ChaCha20-Poly1305, nonce aléatoire"]
    print(f"  {'configuration':38s} {'Pr[gagner]':>10s} {'avantage':>9s}  verdict")
    for nom in configs:
        gagnees = sum(une_partie(nom) for _ in range(n_parties))
        p = gagnees / n_parties
        avantage = abs(2 * p - 1)                            # 0 = sûr, 1 = cassé
        verdict = "CASSÉ" if avantage > 0.5 else "sûr (IND-CPA)"
        R["E1"].append({"configuration": nom, "parties": n_parties, "pr_gagner": round(p, 4),
                        "avantage": round(avantage, 4), "verdict": verdict})
        print(f"  {nom:38s} {p:10.3f} {avantage:9.3f}  {verdict}")


# ===========================================================================
# E2 — Fuite ECB : blocs chiffrés répétés
# ===========================================================================
def proportion_repetes(data):
    bs = blocs(data)
    vus = {}
    for b in bs:
        vus[b] = vus.get(b, 0) + 1
    repetes = sum(n for n in vus.values() if n > 1)
    return repetes / len(bs)


def journal_transactions(n=2000):
    """Journal synthétique d'opérations de paiement mobile, enregistrements de 64 octets."""
    lignes = []
    for i in range(n):
        typ = rng.choice(["DEPOT   ", "RETRAIT ", "TRANSFER", "PAIEMENT"])
        montant = rng.choice([500, 1000, 2000, 5000, 10000, 25000])
        lignes.append(f"TYPE={typ};DEVISE=XOF;MONTANT={montant:08d};TEL=77{rng.randrange(10**7):07d};".ljust(64, "#"))
    return "".join(lignes).encode()


def image_pixels():
    try:
        from PIL import Image
        chemin = os.path.join(ICI, "..", "img", "demo_original.png")
        return Image.open(chemin).convert("RGB").tobytes()
    except Exception:
        return None


def E2():
    titre("E2 — Fuite ECB : proportion de blocs chiffrés qui se répètent")
    cle = alea(16)
    donnees = {"journal de 2000 transactions": journal_transactions()}
    img = image_pixels()
    if img:
        donnees["image (demo_original.png)"] = img
    print(f"  {'données':32s} {'clair':>7s} {'ECB':>7s} {'CBC':>7s} {'CTR':>7s} {'GCM':>7s}")
    for nom, m in donnees.items():
        m = m[: len(m) - len(m) % 16]
        res = {
            "clair": proportion_repetes(m),
            "ECB": proportion_repetes(aes(cle, modes.ECB(), m)),
            "CBC": proportion_repetes(aes(cle, modes.CBC(alea(16)), m)),
            "CTR": proportion_repetes(aes(cle, modes.CTR(alea(16)), m)),
            "GCM": proportion_repetes(AESGCM(cle).encrypt(alea(12), m, None)[:-16]),
        }
        R["E2"].append({"donnees": nom, "taille_octets": len(m), **{k: round(v, 4) for k, v in res.items()}})
        print(f"  {nom:32s} " + " ".join(f"{100 * res[k]:6.1f}%" for k in ["clair", "ECB", "CBC", "CTR", "GCM"]))


# ===========================================================================
# E3 — Modifier un bit du chiffré
# ===========================================================================
def E3():
    titre("E3 — Modifier 1 bit du chiffré (octet 20 = bloc 2) : que voit le destinataire ?")
    cle = alea(16)
    m = b"TYPE=TRANSFER;XO" + b"MONTANT=00005000" + b"TEL=770000000;##" + b"FIN-DU-MESSAGE##"
    pos = 20
    print(f"  {'mode':5s} {'accepté ?':10s} {'octets du clair changés':24s} {'blocs touchés':14s} contrôlable ?")
    for mode in ["ECB", "CBC", "CTR", "GCM"]:
        if mode == "GCM":
            g, n = AESGCM(cle), alea(12)
            c = bytearray(g.encrypt(n, m, None)); c[pos] ^= 0x01
            try:
                g.decrypt(n, bytes(c), None); accepte, m2 = True, None
            except InvalidTag:
                accepte, m2 = False, None
        else:
            md = {"ECB": lambda: modes.ECB(), "CBC": lambda: modes.CBC(iv), "CTR": lambda: modes.CTR(iv)}
            iv = alea(16)
            c = bytearray(aes(cle, md[mode](), m)); c[pos] ^= 0x01
            m2, accepte = aes(cle, md[mode](), bytes(c), dec=True), True
        if m2 is not None:
            diff = [i for i in range(len(m)) if m[i] != m2[i]]
            touches = sorted({i // 16 + 1 for i in diff})
            ctrl = {"ECB": "non (bloc aléatoire)", "CBC": "oui sur le bloc suivant",
                    "CTR": "OUI, bit pour bit"}[mode]
        else:
            diff, touches, ctrl = [], [], "rejeté : tag invalide"
        R["E3"].append({"mode": mode, "accepte": accepte, "octets_changes": len(diff),
                        "blocs_touches": touches, "controlable": ctrl})
        print(f"  {mode:5s} {'oui' if accepte else 'NON':10s} {len(diff):<24d} {str(touches):14s} {ctrl}")


# ===========================================================================
# E4 — Attaque par oracle de remplissage sur CBC (Vaudenay 2002)
# ===========================================================================
class ServeurVulnerable:
    """Simule un serveur qui répond « remplissage invalide » ou « OK » : c'est l'oracle."""

    def __init__(self):
        self._cle = alea(16)
        self.requetes = 0

    def chiffrer(self, m):
        iv = alea(16)
        p = padding.PKCS7(128).padder()
        return iv, aes(self._cle, modes.CBC(iv), p.update(m) + p.finalize())

    def remplissage_valide(self, iv, c):
        self.requetes += 1
        clair = aes(self._cle, modes.CBC(iv), c, dec=True)
        u = padding.PKCS7(128).unpadder()
        try:
            u.update(clair) + u.finalize()
            return True
        except ValueError:
            return False


def casser_bloc(serveur, precedent, bloc):
    """Retrouve D_K(bloc) octet par octet grâce à l'oracle ; renvoie le clair du bloc."""
    inter = bytearray(16)
    for pos in range(15, -1, -1):
        p = 16 - pos
        faux = bytearray(16)
        for j in range(pos + 1, 16):
            faux[j] = inter[j] ^ p
        trouve = False
        for g in range(256):
            faux[pos] = g
            if serveur.remplissage_valide(bytes(faux), bloc):
                if p == 1:                                  # vérifier qu'on n'a pas eu 0x02 0x02 par hasard
                    faux[pos - 1] ^= 0xFF
                    ok = serveur.remplissage_valide(bytes(faux), bloc)
                    faux[pos - 1] ^= 0xFF
                    if not ok:
                        continue
                inter[pos] = g ^ p
                trouve = True
                break
        if not trouve:
            raise RuntimeError("octet introuvable")
    return xor(inter, precedent)


def E4():
    titre("E4 — Oracle de remplissage (CBC) : déchiffrer SANS la clé")
    serveur = ServeurVulnerable()
    secret = b"PIN=4821;SOLDE=1250000 XOF;TEL=771234567"
    iv, c = serveur.chiffrer(secret)
    t0 = time.perf_counter()
    morceaux, precedent = [], iv
    for b in blocs(c):
        morceaux.append(casser_bloc(serveur, precedent, b))
        precedent = b
    duree = time.perf_counter() - t0
    clair = b"".join(morceaux)
    clair = clair[: -clair[-1]]                              # retirer le remplissage
    ok = clair == secret
    R["E4"] = {"message_secret_octets": len(secret), "blocs": len(blocs(c)), "requetes_oracle": serveur.requetes,
               "requetes_par_octet": round(serveur.requetes / len(c), 1), "duree_s": round(duree, 3),
               "reussi": ok, "retrouve": clair.decode(errors="replace")}
    print(f"  chiffré : {len(c)} octets ({len(blocs(c))} blocs)")
    print(f"  retrouvé sans la clé : {clair.decode(errors='replace')}")
    print(f"  {serveur.requetes} requêtes à l'oracle (≈ {serveur.requetes / len(c):.0f} par octet), {duree:.2f} s"
          f"  -> {'RÉUSSI' if ok else 'échec'}")


# ===========================================================================
# E5 — Nonce réutilisé en CTR et en GCM
# ===========================================================================
def E5():
    titre("E5 — Nonce réutilisé : Kiné connaît m1 et lit m2 sans la clé")
    m1 = b"VIRE 5000 FCFA A MOUSSA ; PIN=0000"
    m2 = b"VIRE 7500 FCFA A AWA    ; PIN=4821"
    cle = alea(16)
    # CTR
    n = alea(16)
    c1, c2 = aes(cle, modes.CTR(n), m1), aes(cle, modes.CTR(n), m2)
    ctr_ok = xor(c2, xor(c1, m1)) == m2
    # GCM : le chiffrement interne est du CTR, le même nonce donne le même masque
    g, n12 = AESGCM(cle), alea(12)
    g1, g2 = g.encrypt(n12, m1, None)[:-16], g.encrypt(n12, m2, None)[:-16]
    gcm_ok = xor(g2, xor(g1, m1)) == m2
    R["E5"] = {"CTR_m2_retrouve": ctr_ok, "GCM_m2_retrouve": gcm_ok,
               "remarque": "en GCM, la réutilisation permet aussi de forger des tags (Joux 2006), non implémenté ici"}
    print(f"  CTR : m2 retrouvé = {ctr_ok}")
    print(f"  GCM : m2 retrouvé = {gcm_ok}   (même GCM perd la confidentialité si le nonce est réutilisé)")
    print("  + en GCM, Modou peut aussi forger des messages valides (Joux 2006) : théorie, non codé ici")


# ===========================================================================
# E6 — Débit
# ===========================================================================
def debit(fonction, taille, repetitions):
    mesures = []
    for _ in range(repetitions):
        t0 = time.perf_counter(); fonction(); mesures.append(time.perf_counter() - t0)
    return taille / statistics.median(mesures) / 1e6


def E6(taille_mo, repetitions):
    titre(f"E6 — Débit de chiffrement ({taille_mo} Mo, médiane de {repetitions} mesures)")
    data = alea(taille_mo * 1_000_000 // 16 * 16)
    cle, cle32 = alea(16), alea(32)
    tests = {
        "AES-128-ECB": lambda: aes(cle, modes.ECB(), data),
        "AES-128-CBC": lambda: aes(cle, modes.CBC(alea(16)), data),
        "AES-128-CTR": lambda: aes(cle, modes.CTR(alea(16)), data),
        "AES-128-GCM": lambda: AESGCM(cle).encrypt(alea(12), data, None),
        "ChaCha20-Poly1305": lambda: ChaCha20Poly1305(cle32).encrypt(alea(12), data, None),
    }
    for nom, f in tests.items():
        v = debit(f, len(data), repetitions)
        R["E6"].append({"algorithme": nom, "debit_Mo_s": round(v, 1)})
        print(f"  {nom:20s} {v:9.1f} Mo/s")


# ===========================================================================
def ecrire_resultats():
    with open(os.path.join(SORTIE, "resultats.json"), "w", encoding="utf-8") as f:
        json.dump(R, f, ensure_ascii=False, indent=2)
    L = ["# Résultats du banc d'essai A1", "", f"Environnement : `{json.dumps(R['meta'], ensure_ascii=False)}`", "",
         "## E1 — Jeu IND-CPA", "| Configuration | Pr[gagner] | Avantage | Verdict |", "|---|---|---|---|"]
    L += [f"| {e['configuration']} | {e['pr_gagner']} | {e['avantage']} | {e['verdict']} |" for e in R["E1"]]
    L += ["", "## E2 — Blocs chiffrés répétés", "| Données | Clair | ECB | CBC | CTR | GCM |", "|---|---|---|---|---|---|"]
    L += [f"| {e['donnees']} | " + " | ".join(f"{100 * e[k]:.1f} %" for k in ["clair", "ECB", "CBC", "CTR", "GCM"]) + " |"
          for e in R["E2"]]
    L += ["", "## E3 — Un bit modifié", "| Mode | Accepté | Octets changés | Blocs touchés | Contrôlable |",
          "|---|---|---|---|---|"]
    L += [f"| {e['mode']} | {'oui' if e['accepte'] else 'NON'} | {e['octets_changes']} | {e['blocs_touches']} | {e['controlable']} |"
          for e in R["E3"]]
    e4 = R["E4"]
    L += ["", "## E4 — Oracle de remplissage", f"- Retrouvé sans la clé : `{e4['retrouve']}` ({'réussi' if e4['reussi'] else 'échec'})",
          f"- {e4['requetes_oracle']} requêtes ({e4['requetes_par_octet']} par octet), {e4['duree_s']} s"]
    L += ["", "## E5 — Nonce réutilisé", f"- CTR : m2 retrouvé = {R['E5']['CTR_m2_retrouve']}",
          f"- GCM : m2 retrouvé = {R['E5']['GCM_m2_retrouve']}", f"- {R['E5']['remarque']}"]
    L += ["", "## E6 — Débit", "| Algorithme | Mo/s |", "|---|---|"]
    L += [f"| {e['algorithme']} | {e['debit_Mo_s']} |" for e in R["E6"]]
    with open(os.path.join(SORTIE, "resultats.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print(f"\nRésultats écrits dans {SORTIE}/resultats.json et resultats.md")


if __name__ == "__main__":
    R["meta"] = {"date": time.strftime("%Y-%m-%d %H:%M"), "python": platform.python_version(),
                 "cryptography": cryptography.__version__, "machine": platform.machine(),
                 "processeur": platform.processor() or "inconnu", "graine": GRAINE,
                 "mode": "rapide" if RAPIDE else "complet"}
    # une graine par expérience : le résultat de l'une ne dépend pas des tirages faits par les autres
    for k, (experience, args) in enumerate([(E1, (200 if RAPIDE else 2000,)), (E2, ()), (E3, ()), (E4, ()), (E5, ()),
                                            (E6, (8 if RAPIDE else 64, 3 if RAPIDE else 5))], start=1):
        rng.seed(GRAINE + k)
        experience(*args)
    ecrire_resultats()
