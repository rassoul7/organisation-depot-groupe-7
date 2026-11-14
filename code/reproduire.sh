#!/usr/bin/env bash
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
CODE="$RACINE/code"
DONNEES="$RACINE/donnees"
RESULTATS="$RACINE/resultats"

cd "$RACINE"

echo "== Banc d'essai synthétique =="
"$PYTHON" "$CODE/banc_essai.py"
"$PYTHON" "$CODE/deroule_modes.py"
cp "$CODE/resultats/resultats.json" "$CODE/resultats/resultats.md" "$RESULTATS/"

echo
echo "== Détecteur statique sur le pilote =="
"$PYTHON" "$CODE/detecteur.py" \
  "$DONNEES/corpus_pilote.csv" \
  "$DONNEES/apk_pilote" \
  "$RESULTATS/resultats_pilote"

echo
echo "== Détecteur statique sur le témoin vulnérable =="
"$PYTHON" "$CODE/detecteur.py" \
  "$CODE/temoin.csv" \
  "$DONNEES" \
  "$RESULTATS/resultats_temoin"
