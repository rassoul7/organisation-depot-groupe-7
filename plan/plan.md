# Plan du projet A1

## Question de recherche

Comment construire et valider un protocole reproductible de mesure des erreurs de chiffrement dans des applications Android financières, avant son application à un corpus commercial de l'UEMOA ?

## Hypothèse

Un détecteur statique fondé sur la provenance des IV, des nonces et des clés peut retrouver plusieurs mauvais usages connus dans le bytecode Android, à condition d'être validé sur un témoin vulnérable et de distinguer le code de l'application des bibliothèques. Le pilote F-Droid sert à tester la chaîne, mais ne permet pas de généraliser aux applications commerciales de l'UEMOA.

## Méthode prévue

1. Définir neuf règles de détection et les modèles d'attaque associés.
2. Mesurer leurs effets sur des données synthétiques avec six expériences reproductibles.
3. Analyser 12 APK financières open source sélectionnées depuis F-Droid.
4. Vérifier le détecteur sur InsecureBankv2.
5. Documenter les limites et préparer une future collecte d'APK de paiement/mobile money de l'UEMOA.
