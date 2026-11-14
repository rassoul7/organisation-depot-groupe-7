# Questions du discutant — A9 : Consensus BFT pour un consortium universitaire

**Groupe discutant :** groupe 7 (Mouhamadou Rassoul NAME, Ousmane DIALLO, Ndèye Penda NIANG)
**Groupe discuté :** groupe 3 (Souleymane KONE, Fatou Kiné THIOUB, Mouhamadou Makhtar GUEYE), séance S4, jeudi 12 novembre 2026, bloc 2
**Documents lus :** diapositives A9 (PDF, puis version PowerPoint du 12/11, avec les notes de l'orateur), résumé du rapport (1 page), et les attentes de l'enseignant pour A9.

Le sujet est bien motivé (faux diplômes, reconnaissance des diplômes entre pays de l'UEMOA), la borne n ≥ 3f + 1 est démontrée clairement (intersection de deux quorums de 2f + 1, exercice à 10 universités), et le banc CometBFT est une bonne base. Comme le demande la consigne, la première question porte sur la **méthode**, la seconde sur une **hypothèse**.

---

## Question 1 (méthode) — Les latences injectées sont-elles réalistes, et votre mesure peut-elle les voir ?

**Constat.**
- Les retards ajoutés avec tc netem (10 à 45 ms) sont, selon vous, des « **valeurs d'exemple à sourcer** » (diapo 10).
- Ils sont fixés **par nœud** (un retard « aller simple » par université), alors qu'un réseau réel est décrit par une **matrice de latences ville par ville** : le délai Dakar–Niamey n'est pas la somme d'un retard propre à Dakar et d'un retard propre à Niamey. Le trafic entre deux pays d'Afrique de l'Ouest peut aussi passer par l'Europe, ce qui allonge fortement le trajet.
- Vous écrivez vous-mêmes que la latence a un **plancher d'environ 1 s**, fixé par `timeout_commit` (délai entre deux blocs), et que le débit est **limité par votre client de mesure** (diapo 13). Avec un plancher de 1 000 ms, un ajout de 10 à 45 ms est presque **invisible**.
- Les 10 nœuds tournent sur **une seule machine**, avec seulement 3 essais par scénario, et le tableau des résultats a été retiré de la dernière version.

**Question.** D'où viennent vos valeurs de 10 à 45 ms, et pourquoi un retard par nœud plutôt qu'une **matrice de latences mesurées entre les capitales de l'UEMOA** ? Et si la latence est fixée à environ 1 s par `timeout_commit`, comment votre expérience pourrait-elle montrer l'effet du réseau ouest-africain sur le consensus ?

**Ce qu'une bonne réponse devrait contenir.**
- Une **matrice de latences sourcée** entre capitales, à partir de mesures réelles (sondes publiques de mesure réseau, par exemple RIPE Atlas), injectée **par paire de nœuds**.
- La mesure du **temps de consensus lui-même** (de la proposition au commit, dans les journaux des nœuds), ou un `timeout_commit` réduit.
- Un générateur de charge qui ne bloque pas (l'enseignant cite **Hyperledger Caliper**), et plus de répétitions, avec un intervalle de confiance.

---

## Question 2 (hypothèse) — Qui garantit qu'il y aura toujours moins d'un tiers d'universités fautives ?

**Constat.**
- Toute la sécurité repose sur l'hypothèse « au plus f validateurs fautifs, avec n ≥ 3f + 1 » (diapos 2 et 3).
- Vous dites vous-mêmes que si f + 1 universités s'entendent, « les garanties tombent », et que « qui peut écrire […] relève de la gouvernance du consortium » (diapos 8 et 14). Mais **la gouvernance n'est jamais décrite**.
- Dans CometBFT, la **liste des validateurs** peut changer, et ce changement est lui-même une décision validée par le consortium. Une coalition qui contrôle le vote peut donc **faire entrer ses alliés**.
- Votre propre note (exercice à 10 universités) le montre : 2 universités **hors ligne en permanence** consomment déjà 2 des 3 fautes tolérées.

**Question.** Qui décide d'**ajouter ou de retirer une université validatrice** : par exemple une université privée non reconnue, une université dont la clé a été volée, ou un site coupé du réseau depuis des semaines ? Selon quelle règle ? Sans cette règle, qu'est-ce qui garantit que l'hypothèse « moins d'un tiers de fautifs » reste vraie dans le temps ?

**Ce qu'une bonne réponse devrait contenir.**
- Une **règle d'admission et d'exclusion** : qui vote, à quelle majorité, avec quelle autorité extérieure (par exemple le CAMES ou les ministères), et comment retirer un nœud compromis ou durablement hors ligne.
- La **protection des clés des validateurs** (une clé volée équivaut à une université fautive).
- La reconnaissance que la borne 3f + 1 est une **hypothèse sur la gouvernance**, et pas seulement une propriété du protocole.

---

## Relances et questions de réserve
- **Si Q1 reçoit la réponse « c'est une limite, on l'a écrit » :** « Que changerez-vous pour les premiers résultats (S5), pour que la mesure puisse **contredire** votre hypothèse sur la dégradation des performances ? »
- **Si Q2 reçoit la réponse « c'est de la gouvernance, pas notre sujet » :** « Mais votre preuve de sûreté repose entièrement sur f. Si personne ne contrôle qui entre, que vaut la preuve ? »
- **Réserve 1, aucun nœud byzantin testé :** la seule faute testée consiste à **arrêter** un nœud (`docker stop`), c'est-à-dire une **panne franche**, que **Raft** tolère déjà avec moins de nœuds (n ≥ 2f + 1). La démonstration attendue par l'enseignant montre pourtant « le même tour avec un nœud byzantin ». Qu'est-ce que vos résultats montrent que Raft n'aurait pas donné ? Leurs notes prévoient « validateurs réellement byzantins » et « comparaison avec Raft » en perspectives.
- **Réserve 2, faut-il une blockchain ?** Si une autorité commune existe (CAMES), une **signature numérique avec une infrastructure à clé publique (PKI)** ne suffirait-elle pas ? C'est le test de Wüst et Gervais (2018), qu'ils citent eux-mêmes.

---

## Remarques de forme (pour la version corrigée à J+2)
- Page de titre : « Discutants : groupe [3] · Rapporteurs : groupe [7] ». En réalité, les **discutants sont le groupe 7** et les **rapporteurs le groupe 2**. Le pied de page « Groupe [n] » reste à remplacer sur toutes les diapos.
- Il manque le lien de la vidéo de secours (« [lien] », diapo 12), et le tableau des résultats a disparu de la diapo 13.
- La numérotation des références saute ([4], [6], [12] et [13] manquent). BLOCKBENCH (SIGMOD 2017), attendu par l'enseignant, n'est pas cité.
- Les 28, 91 et 190 messages par décision correspondent au calcul de **PBFT**, alors que le banc utilise **CometBFT**, qui diffuse ses votes autrement : à préciser.
- 16 diapos : au-delà de la limite de 12 du dépôt.
- Sigles à développer à leur première utilisation : BFT (*Byzantine Fault Tolerance*), PBFT, ABCI, GST.
