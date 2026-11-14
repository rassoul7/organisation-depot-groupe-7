# Résultats (analyse statique, détecteur v3)

Date : 2026-11-14 00:01

| Métrique | Valeur |
|---|---|
| applis_corpus | 1 |
| non_analysables_flutter_rn | 0 |
| analysables | 1 |
| utilisent_crypto | 1 |
| utilisent_crypto_dans_code_appli | 1 |
| avec_erreur_hors_E1 | 1 |
| prevalence | 1.0 |
| ic95_wilson | [0.207, 1.0] |
| avec_erreur_dans_code_appli | 1 |
| prevalence_code_appli | 1.0 |
| ic95_wilson_code_appli | [0.207, 1.0] |

| Règle | Applis touchées | Constats (appli) | Constats (bibliothèque) |
|---|---|---|---|
| A1 | 0 | 0 | 0 |
| A2 | 0 | 0 | 0 |
| B1 | 1 | 2 | 1 |
| B3 | 0 | 0 | 0 |
| C1 | 1 | 2 | 0 |
| C3 | 0 | 0 | 0 |
| C4 | 0 | 0 | 0 |
| D1 | 1 | 1 | 0 |
| E1 | 1 | 0 | 5 |

## Détail par appli

### com.android.insecurebankv2 (Java/Kotlin, crypto : oui)
Transformations Cipher vues : `AES/CBC/PKCS5Padding [appli]`, `AES/CBC/PKCS5Padding [bibliothèque]`
- **B1** [appli] IvParameterSpec(tableau constant) — `Lcom/android/insecurebankv2/CryptoClass;->aes256decrypt`
- **C1** [appli] SecretKeySpec(tableau constant) — `Lcom/android/insecurebankv2/CryptoClass;->aes256decrypt`
- **B1** [appli] IvParameterSpec(tableau constant) — `Lcom/android/insecurebankv2/CryptoClass;->aes256encrypt`
- **C1** [appli] SecretKeySpec(tableau constant) — `Lcom/android/insecurebankv2/CryptoClass;->aes256encrypt`
- **E1** [bibliothèque] MessageDigest.getInstance("MD5") — `Lcom/google/android/gms/ads/internal/util/client/zza;->zzax`
- **E1** [bibliothèque] MessageDigest.getInstance("SHA1") — `Lcom/google/android/gms/iid/InstanceID;->zza`
- **B1** [bibliothèque] IvParameterSpec(tableau vide (zéros)) — `Lcom/google/android/gms/internal/zzar;->zzc`
- **E1** [bibliothèque] MessageDigest.getInstance("MD5") — `Lcom/google/android/gms/internal/zzbl;->zzcu`
- **E1** [bibliothèque] MessageDigest.getInstance("MD5") — `Lcom/google/android/gms/internal/zzhl;->zzgn`
- **E1** [bibliothèque] MessageDigest.getInstance("MD5") — `Lcom/google/android/gms/internal/zzak;->zza`
- **D1** [appli] modes ['CBC'] sans Mac dans l'appli — `(appli entière)`

