# Synthèse du rapporteur — A11 : Outils d'analyse de contrats Solidity

**Groupe rapporteur :** groupe 7 (Mouhamadou Rassoul NAME, Ousmane DIALLO, Ndèye Penda NIANG)
**Groupe rapporté :** groupe 4 (Mohamed LO, Ahmadoul Khadim TOURE, Amadou Tidiane KANE) — A11, séance S5, vendredi 13 novembre 2026, bloc 3. Discutants : groupe 6.

---

## PARTIE A — Grille à remplir EN DIRECT pendant leur exposé

Coche et note ; ça servira à la fois pour l'oral (juste après) et pour la page écrite.

### Contenu attendu par le professeur (fiche A11) — présent ou non ?
- [ ] EVM et gaz, juste ce qu'il faut : ...
- [x] Réentrance illustrée par **The DAO (2016)** : ...
- [ ] Schéma **vérifier–modifier–interagir** (checks-effects-interactions) comme correctif : ...
- [x] Taxonomie d'Atzei : dépassement, **contrôle d'accès**, dépendance à l'horodatage, **front-running** : ...
- [ ] Les **3 familles d'outils** (statique / symbolique / fuzzing) et ce que chacune peut ou NE peut PAS trouver : ...
- [x] Démo attendue : contrat vulnérable **vidé par un contrat attaquant** sur Hardhat local, **puis Slither** lancé dessus : ...

### Cadre commun (fiche, p.1)
- [x] Question de recherche posée **dès la 1re minute** : ...
- [x] Une **figure** + un **exemple chiffré** (le coffre 11→0 ETH) : ...
- [x] État de l'art ≥ **5 sources primaires** : ... (ils en annoncent 5 : Atzei, Securify, Slither, Durieux, Echidna)
- [x] **Démonstration en direct** (ou vidéo de secours ?) : ...
- [ ] Se termine par la **piste de projet** : ...
- [x] **Chaque membre** prend la parole (les 3) : LO ... / TOURE ... / KANE ...
- [ ] **Temps** : début ___h___ fin ___h___ → durée ____ (cible 20 min + 5 de questions)

### Démo — valeurs à relever (preuves)
- Coffre vulnérable : 11 ETH → ____ en ____ réentrées
- Coffre corrigé (CEI + nonReentrant) : résiste ? oui / non
- Slither sur vulnérable : alerte `reentrancy-eth` impact ____  | sur corrigé : ____ alerte
- La démo tourne-t-elle en direct, ou vidéo de secours ? ...

### Questions du bloc (discutant = groupe 6) — À NOTER, c'est le cœur de « points débattus »
- Question 1 de G6 : ...
- Réponse de G4 : ...
- Question 2 de G6 : ...
- Réponse de G4 : ...
- (G6 doit interroger : la **qualité de la vérité terrain** — qui a annoté les contrats — et le **biais d'un jeu ancien face à Solidity 0.8**. Note si ça sort.)
- Autres questions (prof, salle) : ...

### Remarques de forme repérées
- Pied de page diapos « A11 — Analyse… 1/11 » mais 17 pages PDF / sigles développés ? / « clair »-« chiffré » / etc. : ...

---

## PARTIE B — Synthèse écrite d'une page (brouillon à compléter après l'exposé)

### 1. Question de recherche
Le groupe 4 demande si les outils automatiques **Slither, Mythril et Echidna** détectent les
vulnérabilités **réellement exploitées** des contrats Solidity, et avec quel **taux de faux positifs**
sur des contrats **récents (Solidity 0.8)**. Hypothèse : les outils sont **complémentaires**, les combiner améliore la couverture sans garantir l'absence de faille. Enjeu local : un diplôme de l'ESP vérifié par contrat (sujet A13) reposerait sur ce type de code.

### 2. Mécanisme présenté
Trois familles d'analyse d'un même contrat : **Slither** (analyse statique sur représentation
intermédiaire), **Mythril** (exécution symbolique), **Echidna** (test aléatoire guidé par propriétés),
chacune produisant des alertes ou un contre-exemple, confrontés à une revue manuelle (VP/FP/FN).
Le cas étudié est la **réentrance** : un `retirer()` qui **envoie les fonds avant de mettre l'état à jour**,
ce qui permet à `receive()` de l'attaquant de rappeler la fonction. Correctif : **vérifier–modifier–
interagir** (mettre à jour le solde avant l'appel externe) + `nonReentrant`. [Compléter : clarté de
l'explication et de la figure.]

### 3. Résultats montrés
Sur un réseau **Hardhat local** (mesuré le 10/11/2026, 7 tests sur 7) : le coffre vulnérable passe de
**11 à 0 ETH en 10 réentrées** ; le coffre corrigé conserve les 10 ETH d'Alice. **Slither 0.11.6** signale
`reentrancy-eth` (impact élevé) sur le coffre vulnérable et **aucune** alerte sur le coffre corrigé.
[Compléter : démo en direct réussie ou vidéo de secours ? Mythril et Echidna ont-ils été montrés, ou
seulement Slither ?]

### 4. Points débattus
[À remplir avec les questions du groupe 6 et les réponses.] Points attendus : la **qualité de la vérité
terrain** (qui annote les 20 contrats, selon quels critères) et le **biais d'un corpus ancien** face à
Solidity 0.8 (l'arithmétique étant désormais vérifiée par défaut, les failles de dépassement de
[durieux2020] ne se transposent pas). [Noter la solidité des réponses.]

### 5. Ce qui reste ouvert
La **question officielle n'est pas encore tranchée** : la démo ne porte que sur **un** contrat et **un**
outil (Slither sur la réentrance). Mythril et Echidna ne sont pas encore comparés, et le corpus
d'**au moins 20 contrats annotés**, la **matrice de confusion** et les mesures de **précision / rappel /
temps** (comparées à [durieux2020]) sont annoncés comme résultats à venir (jalon résultats
préliminaires). Limites assumées correctement : analyse sur **réseau local uniquement**, jamais sur un
contrat du réseau principal.

---

## PARTIE C — Mini-synthèse ORALE (à dire juste après leur présentation, ~1 min)

Structure : on remercie, on résume en 3 phrases neutres, on relève 2 points forts et 1 point à creuser.

> « Merci au groupe 4. **Résumé :** ils ont testé si les outils automatiques détectent les vraies failles des contrats Solidity 0.8, en prenant la **réentrance** comme cas d'école : un coffre qui envoie l'argent avant de mettre son solde à jour, vidé de 11 à 0 ETH en 10 réentrées sur Hardhat, puis **Slither** qui repère bien la faille sur la version vulnérable et se tait sur la version corrigée.
>
> **Deux points forts :** la démonstration est **chiffrée et reproductible** (7 tests sur 7, versions d'outils précisées), et les limites sont **honnêtes** — une alerte ne prouve pas qu'une faille est exploitable, une absence d'alerte ne prouve pas la sécurité.
>
> **Ce qui reste à faire**, et c'est le cœur de leur question : la démo ne montre qu'**un outil sur un contrat**. La réponse viendra du **corpus de 20 contrats annotés** avec **Mythril et Echidna**, et la vraie difficulté sera la **qualité de l'annotation** (la vérité terrain) sur des contrats récents. »

(Si une remarque de forme est flagrante — démo en vidéo au lieu du direct, dépassement de temps, membre qui n'a pas parlé — l'ajouter en une phrase.)

---

**Rappel :** la version écrite propre est à déposer **J+2 (dimanche 15/11)** dans `synthese/synthese-rapporteur.md` du dépôt. Elle doit tenir en **1 page** et couvrir les 5 sections ci-dessus (grille du prof : synthèse notée /6).
