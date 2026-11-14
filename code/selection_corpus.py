"""
Pilote A1 — Sélection reproductible du corpus dans le catalogue public F-Droid.

Critères d'inclusion du PILOTE (version allégée du protocole) :
  I1  catégorie F-Droid « Finance Manager » ou « Wallet » (finance, paiement, portefeuilles)
  I2  distribuée publiquement sur F-Droid (open source)
  I4  version suggérée à la date de collecte ; empreinte SHA-256 fournie par F-Droid
  I5  Android
  +   mise à jour depuis le 2024-11-10 (appli maintenue) et APK < 30 Mo (temps d'analyse)
  (I3 « utilisée dans l'UEMOA » n'est PAS appliqué dans le pilote : limite assumée)
Tirage : N applis au hasard parmi les éligibles, graine fixe.

Usage : python3 selection_corpus.py index-v1.json [N]
Sortie : corpus.csv (dans le dossier du script)
"""
import csv
import json
import os
import random
import sys
from datetime import datetime, timezone

INDEX = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 12
GRAINE = 20261111
DEPUIS = datetime(2024, 11, 10, tzinfo=timezone.utc).timestamp() * 1000
TAILLE_MAX = 30 * 1024 * 1024
CATEGORIES = {"Finance Manager", "Wallet"}

with open(INDEX, encoding="utf-8") as f:
    idx = json.load(f)

eligibles = []
for app in idx["apps"]:
    if not CATEGORIES & set(app.get("categories", [])):
        continue
    if app.get("lastUpdated", 0) < DEPUIS:
        continue
    pkg = app["packageName"]
    code = int(app.get("suggestedVersionCode") or 0)
    versions = idx["packages"].get(pkg, [])
    choix = [p for p in versions if int(p.get("versionCode", 0)) == code] or versions[:1]
    if not choix:
        continue
    p = choix[0]
    if p.get("size", 0) > TAILLE_MAX:
        continue
    nom = app.get("name") or (app.get("localized", {}).get("en-US", {}) or {}).get("name") or pkg
    eligibles.append({"package": pkg, "nom": nom, "version": p.get("versionName", ""),
                      "versionCode": p.get("versionCode"), "apk": p["apkName"],
                      "categories": "+".join(sorted(CATEGORIES & set(app["categories"]))),
                      "sha256": p.get("hash", ""), "taille_Mo": round(p.get("size", 0) / 1e6, 1),
                      "maj": datetime.fromtimestamp(app["lastUpdated"] / 1000, timezone.utc).date().isoformat()})

eligibles.sort(key=lambda a: a["package"])
corpus = random.Random(GRAINE).sample(eligibles, min(N, len(eligibles)))

sortie = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus.csv")
with open(sortie, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(corpus[0].keys()))
    w.writeheader()
    w.writerows(corpus)

print(f"Applis financières éligibles : {len(eligibles)} ; tirées : {len(corpus)} (graine {GRAINE})")
for a in corpus:
    print(f"  {a['package']:45s} {a['version']:>12s}  {a['taille_Mo']:5.1f} Mo  maj {a['maj']}")
print(f"-> {sortie}")
