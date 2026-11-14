# Résultats (analyse statique, détecteur v3)

Date : 2026-11-13 23:57

| Métrique | Valeur |
|---|---|
| applis_corpus | 12 |
| non_analysables_flutter_rn | 2 |
| analysables | 10 |
| utilisent_crypto | 5 |
| utilisent_crypto_dans_code_appli | 2 |
| avec_erreur_hors_E1 | 0 |
| prevalence | 0.0 |
| ic95_wilson | [0.0, 0.434] |
| avec_erreur_dans_code_appli | 0 |
| prevalence_code_appli | 0.0 |
| ic95_wilson_code_appli | [0.0, 0.658] |

| Règle | Applis touchées | Constats (appli) | Constats (bibliothèque) |
|---|---|---|---|
| A1 | 0 | 0 | 0 |
| A2 | 0 | 0 | 0 |
| B1 | 0 | 0 | 0 |
| B3 | 0 | 0 | 0 |
| C1 | 0 | 0 | 0 |
| C3 | 0 | 0 | 0 |
| C4 | 0 | 0 | 0 |
| D1 | 0 | 0 | 0 |
| E1 | 0 | 0 | 0 |

## Détail par appli

### io.github.h3yk0.cryo (Java/Kotlin, crypto : oui)

### com.ripster.sossoldi (Flutter, crypto : oui)
Transformations Cipher vues : `? [bibliothèque]`, `AES/CBC/PKCS7Padding [appli]`
- **D1** [appli] modes ['CBC'] sans Mac dans l'appli — `(appli entière)`

### de.freewarepoint.whohasmystuff (Java/Kotlin, crypto : oui)

### com.github.dmitrykouznetsov.softplusoptions (Flutter, crypto : non)

### io.github.kamui2040.vectorint (Java/Kotlin, crypto : non)

### cz.jancejka.spayddecoder (Java/Kotlin, crypto : non)

### com.concealnetwork.concealmobile (Java/Kotlin, crypto : oui)
Transformations Cipher vues : `AES/CBC/PKCS7Padding [bibliothèque]`, `AES/GCM/NoPadding [appli]`

### com.blogspot.e_kanivets.moneytracker (Java/Kotlin, crypto : oui)

### dev.margani.ghest (Java/Kotlin, crypto : non)

### be.chvp.nanoledger (Java/Kotlin, crypto : non)

### app.rapidsplit (Java/Kotlin, crypto : non)

### com.mustafacanyucel.fireflyiiishortcuts (Java/Kotlin, crypto : oui)

