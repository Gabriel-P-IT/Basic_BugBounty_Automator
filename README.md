> **Statut**  
> Toujours en phase de conception. **Ne pas utiliser en production**.

# Bug Bounty Automator v2.3

Script Bash de **reconnaissance automatisée** pour bug bounty et audit web.  
Il enchaîne l’énumération, la validation HTTP, le crawling, le scan de vulnérabilités, la détection de takeovers, le pattern matching et le fuzzing, puis génère un rapport final.

## Objectif

Lancer une **recon complète** d’une cible avec une seule commande.

- **Input** : `example.com`
- **Output** : dossier de résultats + rapport + archive `.tar.gz` optionnelle

---

## Usage

```bash
./bb-automator.sh example.com
./bb-automator.sh 127.0.0.1:8080
./bb-automator.sh example.com "http://127.0.0.1:8080"
./bb-automator.sh --no-archive example.com
./bb-automator.sh --non-interactive example.com
./bb-automator.sh --help
```

### Options

```text
-h, --help             Affiche l’aide et quitte
    --no-archive       Désactive la création de l’archive .tar.gz
    --non-interactive  N’affiche aucun prompt interactif
```

### Mode non interactif

En mode `--non-interactive`, le script applique les choix suivants :

- `GF_MODE=default`
- Wordlist XSS : `XSS-Jhaddix.txt` si elle existe
- Sinon, FFUF XSS est ignoré automatiquement

---

## Workflow

Le script suit ce pipeline :

```text
1. Subfinder     → Énumération de sous-domaines
2. HTTPX         → Validation HTTP des hôtes actifs
3. Katana        → Crawl des URLs
4. Nuclei        → Scan CVE / vulnérabilités
5. Nuclei        → Détection d’expositions / secrets
6. Subzy         → Vérification de subdomain takeover
7. GF            → Extraction de patterns XSS / LFI / SQLi / SSTI
8. FFUF          → Fuzzing XSS sur paramètres candidats
9. Feroxbuster   → Bruteforce de répertoires / fichiers
10. Rapport      → Génération d’un rapport texte
11. Archive      → Compression finale optionnelle
```

### Exécution parallèle

Le script parallélise plusieurs phases pour réduire le temps total :

- `Subfinder` puis `HTTPX`
- `Katana`, `Nuclei` et `Subzy`
- `GF` est exécuté **avant** `FFUF` pour éviter une race condition sur `gf-xss.txt`
- `FFUF` et `Feroxbuster` peuvent ensuite tourner en parallèle

---

## Dépendances

Outils requis :

- `subfinder`
- `httpx`
- `katana`
- `nuclei`
- `subzy`
- `ffuf`
- `feroxbuster`
- `jq`
- `curl`
- `grep`

Si `GF_MODE` n’est pas sur `skip`, il faut aussi :

- `gf`

### Ressources attendues

Le script essaie aussi de trouver :

- une wordlist Feroxbuster de type `directory-list-2.3-medium.txt`
- les templates Nuclei dans `~/nuclei-templates`
- la wordlist XSS Jhaddix dans `/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt`

---

## Fichiers générés

Structure typique :

```text
bb-domain-YYYYMMDD_HHMMSS/
├── subdomains.txt
├── live-raw.txt
├── live.txt
├── urls.txt
├── nuclei-cve.txt
├── nuclei-secrets.txt
├── takeover.txt
├── gf-xss.txt
├── gf-lfi.txt
├── gf-sqli.txt
├── gf-ssti.txt
├── ffuf-xss.json
├── ferox.txt
├── RAPPORT-BUGBOUNTY.txt
└── execution.log
```

### Description des sorties

- `subdomains.txt` : sous-domaines découverts
- `live-raw.txt` : sortie brute HTTPX
- `live.txt` : URLs HTTP valides extraites
- `urls.txt` : URLs trouvées par Katana
- `nuclei-cve.txt` : résultats Nuclei orientés CVE / sévérités medium à critical
- `nuclei-secrets.txt` : résultats Nuclei orientés exposition / token / default-login
- `takeover.txt` : sous-domaines potentiellement vulnérables au takeover
- `gf-xss.txt` : URLs/paramètres candidats XSS
- `gf-lfi.txt` : URLs/paramètres candidats LFI
- `gf-sqli.txt` : URLs/paramètres candidats SQLi
- `gf-ssti.txt` : URLs/paramètres candidats SSTI
- `ffuf-xss.json` : résultats de fuzzing XSS
- `ferox.txt` : contenus découverts par Feroxbuster
- `RAPPORT-BUGBOUNTY.txt` : synthèse finale
- `execution.log` : logs complets d’exécution

Si `--no-archive` n’est **pas** utilisé, une archive finale est aussi créée à côté du dossier :

```text
bb-domain-YYYYMMDD_HHMMSS.tar.gz
```

---

## Fonctionnement

### Validation de la cible

Le script :

- normalise la cible en retirant `http://`, `https://`, `www.` et le slash final
- génère un nom de dossier sûr avec remplacement des caractères spéciaux
- vérifie le format de la cible
- teste la résolution DNS, sauf pour `localhost` / `127.0.0.1`

### Proxy

Un proxy peut être fourni en second argument :

```bash
./bb-automator.sh example.com "http://127.0.0.1:8080"
```

Il est ensuite transmis aux outils qui le supportent.

### Archivage

Par défaut, le script crée une archive `.tar.gz` en fin d’exécution.  
Utilise `--no-archive` pour désactiver cette étape.

---

## Limitations

- Le script n’est **pas** prévu pour un usage production à ce stade.
- Le temps d’exécution dépend fortement de la taille de la cible et des timeouts configurés.
- Certains outils peuvent produire des résultats partiels ou silencieux si un timeout est atteint.
- `ffuf-xss.json` peut contenir une concaténation de sorties JSON, donc il n’est pas forcément directement exploitable comme JSON unique.
- La validation de domaine reste volontairement assez stricte.

---

## Exemples

### Scan standard

```bash
./bb-automator.sh example.com
```

### Scan via Burp

```bash
./bb-automator.sh example.com "http://127.0.0.1:8080"
```

### Cible locale

```bash
./bb-automator.sh 127.0.0.1:8080
```

### Sans archive

```bash
./bb-automator.sh --no-archive example.com
```

### Sans interaction

```bash
./bb-automator.sh --non-interactive example.com
```

---

## Avertissement

Utiliser uniquement sur des cibles **autorisées** dans un cadre légal : bug bounty, lab personnel, environnement de test ou audit contractualisé.
