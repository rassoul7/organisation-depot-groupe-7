# Résultats du banc d'essai A1

Environnement : `{"date": "2026-11-13 23:57", "python": "3.12.15", "cryptography": "50.0.2", "machine": "x86_64", "processeur": "inconnu", "graine": 20261111, "mode": "complet"}`

## E1 — Jeu IND-CPA
| Configuration | Pr[gagner] | Avantage | Verdict |
|---|---|---|---|
| ECB | 1.0 | 1.0 | CASSÉ |
| CBC, IV fixe | 1.0 | 1.0 | CASSÉ |
| CBC, IV prévisible (compteur) | 1.0 | 1.0 | CASSÉ |
| CBC, IV aléatoire | 0.5195 | 0.039 | sûr (IND-CPA) |
| CTR, nonce fixe | 1.0 | 1.0 | CASSÉ |
| CTR, nonce aléatoire | 0.4895 | 0.021 | sûr (IND-CPA) |
| GCM, nonce fixe | 1.0 | 1.0 | CASSÉ |
| GCM, nonce aléatoire | 0.5045 | 0.009 | sûr (IND-CPA) |
| ChaCha20-Poly1305, nonce aléatoire | 0.4905 | 0.019 | sûr (IND-CPA) |

## E2 — Blocs chiffrés répétés
| Données | Clair | ECB | CBC | CTR | GCM |
|---|---|---|---|---|---|
| journal de 2000 transactions | 75.0 % | 75.0 % | 0.0 % | 0.0 % | 0.0 % |

## E3 — Un bit modifié
| Mode | Accepté | Octets changés | Blocs touchés | Contrôlable |
|---|---|---|---|---|
| ECB | oui | 16 | [2] | non (bloc aléatoire) |
| CBC | oui | 17 | [2, 3] | oui sur le bloc suivant |
| CTR | oui | 1 | [2] | OUI, bit pour bit |
| GCM | NON | 0 | [] | rejeté : tag invalide |

## E4 — Oracle de remplissage
- Retrouvé sans la clé : `PIN=4821;SOLDE=1250000 XOF;TEL=771234567` (réussi)
- 5760 requêtes (120.0 par octet), 0.041 s

## E5 — Nonce réutilisé
- CTR : m2 retrouvé = True
- GCM : m2 retrouvé = True
- en GCM, la réutilisation permet aussi de forger des tags (Joux 2006), non implémenté ici

## E6 — Débit
| Algorithme | Mo/s |
|---|---|
| AES-128-ECB | 565.7 |
| AES-128-CBC | 406.0 |
| AES-128-CTR | 979.2 |
| AES-128-GCM | 926.2 |
| ChaCha20-Poly1305 | 581.1 |
