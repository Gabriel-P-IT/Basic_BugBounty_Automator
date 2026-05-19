# Toujours en phase de conception ! Ne pas utiliser en prod

# Bug Bounty Automator v2.3
## Reconnaissance Automatisée Bug Bounty

### 🎯 Objectif
Script qui exécute une **reconnaissance complète** d'une cible en une seule commande.

**Input** : `example.com`  
**Output** : Rapport + archive complète des résultats

---

## 🚀 Usage Simple
```bash
./bb-automator.sh example.com                    # Scan standard
./bb-automator.sh 127.0.0.1:8080                    # Local vuln (Juice Shop)
./bb-automator.sh example.com "http://burp:8080"       # Via Burp proxy
./bb-automator.sh example.com "" 3                   # Skip FFUF (rapide)
```

**Durée** : 20-45 minutes selon la taille de la cible

---

## 📋 Workflow Automatisé (8 Phases)

```
1️⃣ SUBFINDER    → 63 sous-domaines
2️⃣ HTTPX       → 22 hôtes actifs  
3️⃣ KATANA      → 200+ URLs crawlées
4️⃣ NUCLEI CVE  → Vulnérabilités détectées
5️⃣ NUCLEI SEC  → Secrets/API keys exposés
6️⃣ SUBZY       → Takeover sous-domaines
7️⃣ GF PATTERNS → Params XSS/LFI/SQLi/SSTI
8️⃣ FUZZING     → XSS + Directory brute-force
↓
RAPPORT + archive.tar.gz
```

---

## 📤 Fichiers Générés
```
bb-domain-YYYYMMDD_HHMMSS/
├── subdomains.txt           # Tous les sous-domaines
├── live.txt                 # Hosts HTTP 200/301/302
├── urls.txt                 # URLs crawlées (Katana)
├── nuclei-cve.json          # CVE + vulnérabilités
├── nuclei-secrets.json      # Tokens, API keys, creds
├── takeover.txt             # Subdomain takeovers
├── gf-xss.txt               # Paramètres XSS vulnérables
├── gf-lfi.txt               # Paramètres LFI
├── gf-sqli.txt              # Paramètres SQLi
├── gf-ssti.txt              # Paramètres SSTI
├── ffuf-xss.json            # Résultats fuzzing XSS
├── ferox.txt                # Dossiers/fichiers cachés
├── RAPPORT-BUGBOUNTY.txt    # Synthèse complète
├── execution.log            # Logs détaillés
└── archive.tar.gz           # Tout compressé
```

