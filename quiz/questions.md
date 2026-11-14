# Quiz A1 — Modes AES

## Question 1

Quel est le principal problème d'ECB ?

A. Il ne chiffre jamais les données.  
B. Deux blocs de texte en clair identiques produisent deux blocs de texte chiffré identiques.  
C. Il exige un nonce aléatoire.  
D. Il fournit une authentification forte.

**Réponse : B.** ECB révèle les répétitions et la structure des données ; il ne doit pas être utilisé pour chiffrer des messages structurés.

## Question 2

Quelle condition est indispensable pour utiliser AES-GCM correctement ?

A. Réutiliser le même nonce pour simplifier le stockage.  
B. Utiliser un nonce unique pour chaque chiffrement avec une même clé.  
C. Écrire la clé dans le code source.  
D. Supprimer le tag d'authentification.

**Réponse : B.** La réutilisation d'un nonce GCM peut compromettre la confidentialité et l'authentification.

## Question 3

Que mesure principalement une analyse statique d'APK ?

A. Le comportement observé sur un serveur réel.  
B. Les valeurs réellement utilisées dans toutes les exécutions.  
C. Des motifs présents dans le bytecode, sans exécuter l'application.  
D. La sécurité physique du téléphone.

**Réponse : C.** Une alerte statique est un indice à vérifier ; elle peut produire des faux positifs ou manquer des comportements construits à l'exécution.
