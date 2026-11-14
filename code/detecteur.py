"""
Pilote A1 — Détecteur statique de mauvais usages de la cryptographie dans des APK Android (v2).

Lit le bytecode Dalvik (DEX) avec Androguard, SANS exécuter l'application et SANS contacter
aucun serveur. Règles issues de la taxonomie du protocole (familles A à E) :

  A1  ECB explicite ou par défaut      Cipher.getInstance("AES") ou "AES/ECB/..."
  A2  algorithme faible                Cipher.getInstance("DES" | "DESede" | "RC4" | "Blowfish" ...)
  B1  IV constant                      IvParameterSpec(tableau constant ou vide = zéros)
  B3  nonce GCM constant               GCMParameterSpec(t, tableau constant ou vide)
  C1  clé codée en dur                 SecretKeySpec(tableau constant, ...) (ex. "cle".getBytes())
  C3  peu d'itérations PBE             PBEKeySpec(..., iterations < 1000, ...)
  C4  graine fixe                      SecureRandom.setSeed(...)
  D1  CBC/CTR sans MAC (suspect)       mode CBC ou CTR dans le code de l'appli et aucun Mac dans l'appli
  E1  hachage faible (information)     MessageDigest.getInstance("MD5" | "SHA-1")

v3 : analyse INTER-PROCÉDURALE légère (après le témoin positif InsecureBankv2) : champs qui reçoivent
  toujours une constante, et constantes passées en paramètre d'une méthode de l'appli (3 passes).
v2 (après vérification manuelle du pilote v1) :
  - suivi de PROVENANCE du tableau d'octets passé comme IV / nonce / clé (constante, tableau vide,
    tirage SecureRandom, ou donnée venue d'ailleurs) au lieu d'une heuristique « la méthode contient une
    constante » qui produisait des faux positifs (IV relu depuis le stockage) ;
  - ORIGINE : « bibliothèque » seulement pour des préfixes de bibliothèques connues, sinon « appli ».

Usage : python3 detecteur.py fichier.csv dossier_apk [prefixe_sortie]
Sorties : <prefixe>.json et <prefixe>.md (par défaut resultats_pilote.*, dans le dossier du script)
"""
import csv
import json
import math
import os
import re
import sys
import time

from loguru import logger

logger.remove()
from androguard.core.apk import APK  # noqa: E402
from androguard.core.dex import DEX  # noqa: E402

ICI = os.path.dirname(os.path.abspath(__file__))
FAIBLES = ("DES", "DESEDE", "TRIPLEDES", "RC4", "ARC4", "ARCFOUR", "BLOWFISH", "RC2")
BIBLIOTHEQUES = ("Landroid/", "Landroidx/", "Lcom/google/", "Lkotlin/", "Lkotlinx/", "Lokhttp3/", "Lokio/",
                 "Lorg/bouncycastle/", "Lorg/spongycastle/", "Lretrofit2/", "Lcom/squareup/", "Lio/reactivex/",
                 "Lorg/json/", "Ldagger/", "Ljavax/", "Ljava/", "Lorg/apache/", "Lcom/fasterxml/", "Lorg/slf4j/",
                 "Lcom/facebook/", "Lio/flutter/", "Lorg/chromium/", "Lcom/bumptech/", "Lorg/jetbrains/",
                 "Lcom/airbnb/", "Lio/sentry/", "Lcom/microsoft/", "Lnet/sqlcipher/", "Lorg/conscrypt/",
                 "Lcom/journeyapps/", "Lorg/intellij/", "Lcom/sun/", "Lorg/w3c/", "Lorg/xml/", "Lj$/")
RE_INVOKE = re.compile(r"^(.*?)(L[^;]+;->[^(]+\(.*)$")
CONSTANT = ("tableau constant", "tableau vide (zéros)")


def registres(partie):
    """'v0, v1, v2' ou 'v0 ... v3' -> liste de registres."""
    partie = partie.strip().rstrip(",")
    m = re.match(r"v(\d+) \.\.\. v(\d+)", partie)
    if m:
        return [f"v{i}" for i in range(int(m.group(1)), int(m.group(2)) + 1)]
    return [r.strip() for r in partie.split(",") if r.strip().startswith(("v", "p"))]


def origine(classe):
    return "bibliothèque" if classe.startswith(BIBLIOTHEQUES) else "appli"


RE_CHAMP = re.compile(r"(L[^;]+;->\S+ \S+)\s*$")


def sans_espaces(s):
    return s.replace(" ", "")


def types_parametres(descripteur):
    """'([B Ljava/lang/String; I)V' -> ['[B', 'Ljava/lang/String;', 'I']"""
    d = sans_espaces(descripteur)
    d = d[d.index("(") + 1:d.index(")")]
    out, i = [], 0
    while i < len(d):
        j = i
        while d[j] == "[":
            j += 1
        if d[j] == "L":
            j = d.index(";", j)
        out.append(d[i:j + 1])
        i = j + 1
    return out


def registres_parametres(m):
    """Registres Dalvik des paramètres d'une méthode (sans 'this')."""
    code = m.get_code()
    debut = code.get_registers_size() - code.get_ins_size()
    if not (m.get_access_flags() & 0x8):     # méthode non statique : le premier registre est 'this'
        debut += 1
    regs, r = [], debut
    for t in types_parametres(m.get_descriptor()):
        regs.append(f"v{r}")
        r += 2 if t in ("J", "D") else 1
    return regs


def cle_methode(classe, nom, descripteur):
    return f"{classe}->{nom}{sans_espaces(descripteur)}"


def parcourir(m, contexte, constats=None, etat=None):
    """Parcourt une méthode en suivant la provenance des registres.
    contexte = {"champs": {champ: provenance}, "params": {cle_methode: {indice: provenance}},
                "appels": {cle_methode: {indice: set(provenances)}} (rempli ici), "champs_vus": {...}}"""
    classe = m.get_class_name()
    org = origine(classe)
    lieu = f"{classe}->{m.get_name()}"
    regs = {}
    cle = cle_methode(classe, m.get_name(), m.get_descriptor())
    for i, r in enumerate(registres_parametres(m)):
        p = contexte["params"].get(cle, {}).get(i)
        if p is not None:
            regs[r] = p
    resultat = "autre"

    def note(regle, detail):
        if constats is not None:
            constats.append({"regle": regle, "detail": detail, "lieu": lieu, "origine": org})

    def prov(r):
        v = regs.get(r, "autre")
        return v if isinstance(v, str) else v[0]

    for ins in m.get_instructions():
        nom, sortie = ins.get_name(), ins.get_output()
        if nom.startswith("const-string"):
            r, _, s = sortie.partition(", ")
            regs[r.strip()] = ("str", s.strip().strip('"'))
            continue
        if nom in ("const/4", "const/16", "const", "const/high16"):
            r, _, v = sortie.partition(", ")
            try:
                regs[r.strip()] = ("int", int(v.strip(), 0))
            except ValueError:
                regs[r.strip()] = "autre"
            continue
        if nom == "new-array":
            regs[sortie.split(",")[0].strip()] = "tableau vide (zéros)"
            continue
        if nom == "fill-array-data":
            regs[sortie.split(",")[0].strip()] = "tableau constant"
            continue
        if nom.startswith("aput"):
            rs = registres(sortie)
            if len(rs) > 1 and regs.get(rs[1]) == "tableau vide (zéros)":
                regs[rs[1]] = "tableau constant"
            continue
        if nom.startswith(("iput", "sput")):
            mc = RE_CHAMP.search(sortie)
            if mc:
                v = regs.get(sortie.split(",")[0].strip(), "autre")
                vu = contexte["champs_vus"].setdefault(mc.group(1), set())
                vu.add(v if isinstance(v, str) else (v[0] + ":" + str(v[1])))
                if v == "autre" or v == "aléa":
                    contexte["champs_non_constants"].add(mc.group(1))
                else:
                    contexte["champs_candidats"].setdefault(mc.group(1), v)
            continue
        if nom.startswith(("iget", "sget")):
            mc = RE_CHAMP.search(sortie)
            dest = sortie.split(",")[0].strip()
            regs[dest] = contexte["champs"].get(mc.group(1), "autre") if mc else "autre"
            continue
        if nom.startswith("move-result"):
            regs[sortie.strip()] = resultat
            continue
        if nom.startswith("move-object") or nom == "move":
            rs = registres(sortie)
            if len(rs) == 2:
                regs[rs[0]] = regs.get(rs[1], "autre")
            continue
        if not nom.startswith("invoke"):
            premier = sortie.split(",")[0].strip()
            if premier.startswith(("v", "p")) and not nom.startswith(("if-", "return", "throw", "goto",
                                                                      "check-cast", "monitor", "fill-array")):
                regs[premier] = "autre"
            continue

        m_inv = RE_INVOKE.match(sortie)
        resultat = "autre"
        if not m_inv:
            continue
        args, cible = registres(m_inv.group(1)), m_inv.group(2)

        # appels vers une méthode de l'appli : on mémorise ce qu'on lui passe (analyse inter-procédurale)
        if not cible.startswith(BIBLIOTHEQUES):
            nom_m = cible.split("->")[0] + "->" + cible.split("->")[1].split("(")[0]
            desc = "(" + cible.split("(", 1)[1]
            cle_c = cle_methode(cible.split("->")[0], cible.split("->")[1].split("(")[0], desc)
            decal = 0 if nom.startswith("invoke-static") else 1
            types, k = types_parametres(desc), decal
            for i, t in enumerate(types):
                if k < len(args):
                    v = regs.get(args[k], "autre")
                    contexte["appels"].setdefault(cle_c, {}).setdefault(i, set()).add(v)
                k += 2 if t in ("J", "D") else 1
            del nom_m

        if etat is None:
            if cible.startswith("Ljava/lang/String;->getBytes") or "Base64;->decode(Ljava/lang/String;" in cible:
                resultat = "tableau constant" if args and isinstance(regs.get(args[0]), tuple) and regs[args[0]][0] == "str" else "autre"
            elif cible.startswith("Ljava/security/SecureRandom;->nextBytes") and len(args) > 1:
                regs[args[1]] = "aléa"
            continue

        if "Ljavax/crypto/" in cible:
            etat["crypto"] = True
            if org == "appli":
                etat["crypto_appli"] = True
        if cible.startswith("Ljava/lang/String;->getBytes") or "Base64;->decode(Ljava/lang/String;" in cible:
            resultat = "tableau constant" if args and isinstance(regs.get(args[0]), tuple) and regs[args[0]][0] == "str" else "autre"
        elif cible.startswith("Ljava/security/SecureRandom;->nextBytes"):
            if len(args) > 1:
                regs[args[1]] = "aléa"
        elif cible.startswith("Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;"):
            t = regs.get(args[0]) if args else None
            t = t[1] if isinstance(t, tuple) and t[0] == "str" else "?"
            etat["transformations"].append(f"{t} [{org}]")
            tu = str(t).upper()
            if org == "appli":
                for mode in ("CBC", "CTR", "GCM", "ECB"):
                    if f"/{mode}/" in tu or tu.endswith(f"/{mode}"):
                        etat["modes_appli"].add(mode)
            if tu == "AES" or tu.startswith("AES/ECB"):
                note("A1", f'Cipher.getInstance("{t}")')
            elif tu.split("/")[0] in FAIBLES:
                note("A2", f'Cipher.getInstance("{t}")')
        elif cible.startswith("Ljavax/crypto/Mac;->getInstance"):
            if org == "appli":
                etat["mac_appli"] = True
        elif cible.startswith("Ljavax/crypto/spec/IvParameterSpec;-><init>("):
            p = prov(args[1]) if len(args) > 1 else "autre"
            if p in CONSTANT:
                note("B1", f"IvParameterSpec({p})")
        elif cible.startswith("Ljavax/crypto/spec/GCMParameterSpec;-><init>("):
            p = prov(args[2]) if len(args) > 2 else "autre"
            if p in CONSTANT:
                note("B3", f"GCMParameterSpec({p})")
        elif cible.startswith("Ljavax/crypto/spec/SecretKeySpec;-><init>("):
            p = prov(args[1]) if len(args) > 1 else "autre"
            if p in CONSTANT:
                note("C1", f"SecretKeySpec({p})")
        elif cible.startswith("Ljavax/crypto/spec/PBEKeySpec;-><init>([C[BI") or cible.startswith("Ljavax/crypto/spec/PBEKeySpec;-><init>([C [B I"):
            it = regs.get(args[3]) if len(args) > 3 else None
            if isinstance(it, tuple) and it[0] == "int" and it[1] < 1000:
                note("C3", f"PBEKeySpec avec {it[1]} itérations")
        elif cible.startswith("Ljava/security/SecureRandom;->setSeed"):
            note("C4", "SecureRandom.setSeed(...)")
        elif cible.startswith("Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;"):
            t = regs.get(args[0]) if args else None
            t = t[1] if isinstance(t, tuple) and t[0] == "str" else "?"
            if str(t).upper().replace("-", "") in ("MD5", "SHA1", "SHA"):
                note("E1", f'MessageDigest.getInstance("{t}")')


def analyser_apk(chemin):
    a = APK(chemin)
    libs = [f for f in a.get_files() if f.startswith("lib/")]
    cadre = "Flutter" if any("libflutter" in f for f in libs) else (
        "React Native" if any("reactnative" in f or "hermes" in f for f in libs) else "Java/Kotlin")
    methodes = [m for brut in a.get_all_dex() for m in DEX(brut).get_encoded_methods() if m.get_code() is not None]
    ctx = {"champs": {}, "params": {}, "appels": {}, "champs_vus": {}, "champs_candidats": {},
           "champs_non_constants": set()}
    # Passe 1 : champs qui reçoivent toujours une constante
    for m in methodes:
        parcourir(m, ctx)
    ctx["champs"] = {c: v for c, v in ctx["champs_candidats"].items() if c not in ctx["champs_non_constants"]}
    # Passe 2 : ce que chaque appel passe aux méthodes de l'appli (avec les champs constants connus)
    ctx["appels"] = {}
    for m in methodes:
        parcourir(m, ctx)
    ctx["params"] = {}
    for cle, par_indice in ctx["appels"].items():
        for i, provs in par_indice.items():
            const = [p for p in provs if (p if isinstance(p, str) else p[0]) in CONSTANT or (isinstance(p, tuple) and p[0] == "str")]
            if const:                                  # au moins un appel passe une constante
                ctx["params"].setdefault(cle, {})[i] = const[0]
    # Passe 3 : détection
    constats = []
    etat = {"crypto": False, "crypto_appli": False, "modes_appli": set(), "mac_appli": False, "transformations": []}
    for m in methodes:
        parcourir(m, ctx, constats, etat)
    # dédoublonner (même règle, même lieu)
    vus, uniques = set(), []
    for c in constats:
        k = (c["regle"], c["lieu"], c["detail"])
        if k not in vus:
            vus.add(k)
            uniques.append(c)
    if etat["modes_appli"] & {"CBC", "CTR"} and not etat["mac_appli"]:
        uniques.append({"regle": "D1", "detail": f"modes {sorted(etat['modes_appli'])} sans Mac dans l'appli",
                        "lieu": "(appli entière)", "origine": "appli"})
    return {"cadre": cadre, "crypto": etat["crypto"], "crypto_appli": etat["crypto_appli"],
            "modes_appli": sorted(etat["modes_appli"]), "transformations": sorted(set(etat["transformations"])),
            "constats": uniques}



def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, c - h), min(1.0, c + h))


if __name__ == "__main__":
    corpus = list(csv.DictReader(open(sys.argv[1], encoding="utf-8")))
    dossier = sys.argv[2]
    prefixe = sys.argv[3] if len(sys.argv) > 3 else os.path.join(ICI, "resultats_pilote")
    res = {"date": time.strftime("%Y-%m-%d %H:%M"), "version_detecteur": 3, "applis": []}
    for r in corpus:
        t0 = time.time()
        d = analyser_apk(os.path.join(dossier, r["apk"]))
        d.update({"package": r["package"], "version": r.get("version", ""), "sha256": r.get("sha256", ""),
                  "duree_s": round(time.time() - t0, 1)})
        res["applis"].append(d)
        ra = sorted({c["regle"] for c in d["constats"] if c["origine"] == "appli"})
        rb = sorted({c["regle"] for c in d["constats"] if c["origine"] != "appli"})
        print(f"{r['package']:45s} {d['cadre']:12s} crypto={'oui' if d['crypto'] else 'non':3s} "
              f"appli={ra} biblio={rb} ({d['duree_s']} s)", flush=True)

    A = res["applis"]
    analysables = [a for a in A if a["cadre"] == "Java/Kotlin"]
    crypto = [a for a in analysables if a["crypto"]]
    crypto_appli = [a for a in analysables if a["crypto_appli"]]
    def erreur(a, seulement_appli=False):
        return any(c["regle"] != "E1" and (not seulement_appli or c["origine"] == "appli") for c in a["constats"])
    avec_err = [a for a in crypto if erreur(a)]
    avec_err_appli = [a for a in crypto_appli if erreur(a, True)]
    regles = ["A1", "A2", "B1", "B3", "C1", "C3", "C4", "D1", "E1"]
    par_regle = {g: {"applis": sum(any(c["regle"] == g for c in a["constats"]) for a in crypto),
                     "appli": sum(c["regle"] == g and c["origine"] == "appli" for a in crypto for c in a["constats"]),
                     "bibliotheque": sum(c["regle"] == g and c["origine"] != "appli" for a in crypto for c in a["constats"])}
                 for g in regles}
    ic = wilson(len(avec_err), len(crypto))
    ic_a = wilson(len(avec_err_appli), len(crypto_appli))
    res["metriques"] = {
        "applis_corpus": len(A), "non_analysables_flutter_rn": len(A) - len(analysables),
        "analysables": len(analysables), "utilisent_crypto": len(crypto),
        "utilisent_crypto_dans_code_appli": len(crypto_appli),
        "avec_erreur_hors_E1": len(avec_err),
        "prevalence": round(len(avec_err) / len(crypto), 3) if crypto else None,
        "ic95_wilson": [round(ic[0], 3), round(ic[1], 3)],
        "avec_erreur_dans_code_appli": len(avec_err_appli),
        "prevalence_code_appli": round(len(avec_err_appli) / len(crypto_appli), 3) if crypto_appli else None,
        "ic95_wilson_code_appli": [round(ic_a[0], 3), round(ic_a[1], 3)],
        "par_regle": par_regle,
    }
    with open(prefixe + ".json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)

    M = res["metriques"]
    L = ["# Résultats (analyse statique, détecteur v3)", "", f"Date : {res['date']}", "",
         "| Métrique | Valeur |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in M.items() if k != "par_regle"]
    L += ["", "| Règle | Applis touchées | Constats (appli) | Constats (bibliothèque) |", "|---|---|---|---|"]
    L += [f"| {g} | {v['applis']} | {v['appli']} | {v['bibliotheque']} |" for g, v in par_regle.items()]
    L += ["", "## Détail par appli", ""]
    for a in A:
        L.append(f"### {a['package']} ({a['cadre']}, crypto : {'oui' if a['crypto'] else 'non'})")
        if a["transformations"]:
            L.append("Transformations Cipher vues : " + ", ".join(f"`{t}`" for t in a["transformations"]))
        for c in a["constats"]:
            L.append(f"- **{c['regle']}** [{c['origine']}] {c['detail']} — `{c['lieu']}`")
        L.append("")
    with open(prefixe + ".md", "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("\n=== Métriques ===")
    for k, v in M.items():
        if k != "par_regle":
            print(f"  {k:36s} {v}")
    print("  par règle (applis touchées) :", {g: v["applis"] for g, v in par_regle.items()})
