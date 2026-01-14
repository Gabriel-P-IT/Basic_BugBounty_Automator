#!/bin/bash

# Bug Bounty Automator v1.0

set -e  # Stop on error

TARGET=$1
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target.com>"
  exit 1
fi

echo "Bug Bounty Automator v1.0 - $TARGET"
mkdir -p bb-$TARGET
cd bb-$TARGET

# ================
# CHECK TOOLS 
# ================
echo "Vérification des dépendances..."

TOOLS=("subfinder" "httpx" "katana" "nuclei" "subzy" "gf" "bxss" "feroxbuster")
MISSING=()

for tool in "${TOOLS[@]}"; do
  if ! command -v $tool &> /dev/null; then
    MISSING+=($tool)
  fi
done

if [ ${#MISSING[@]} -ne 0 ]; then
  echo "Outils manquants : ${MISSING[*]}"
  exit 1
fi

echo "Tous les tools sont présents"

# ========================================
# CHOIX WORDLIST
# ========================================
echo ""
echo "Choix de la wordlist pour Feroxbuster :"
echo "[1] directory-list-2.3-medium.txt"
echo "[2] directory-list-2.3-small.txt (rapide)"
echo "[3] common.txt (ultra-rapide)"
echo "[4] Personnalisée (chemin absolu)"

read -p "Choix (1-4) : " CHOIX

case $CHOIX in
  1) WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ;;
  2) WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt" ;;
  3) WORDLIST="/usr/share/wordlists/dirbuster/common.txt" ;;
  4) read -p "Chemin wordlist : " WORDLIST ;;
  *) echo "Choix invalide, utilisation medium" ; WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ;;
esac

echo "Wordlist : $WORDLIST"

# ========================================
# Début du WOrkflow
# ========================================
echo ""
echo "Début du Workflow"

# 1. Subdomains
echo "[1/9] Subfinder..."
subfinder -d $TARGET -silent -o subdomains.txt 2>/dev/null || echo "Subfinder OK"

# 2. Live hosts
echo "[2/9] Httpx..."
cat subdomains.txt | httpx -silent -status-code -mc 200,301,302,403 -o live.txt

# 3. Crawling
echo "[3/9] Katana..."
timeout 300 cat live.txt | katana -silent -o urls.txt

# 4. Nuclei secrets
echo "[4/9] Nuclei secrets..."
cat urls.txt | nuclei -t ~/nuclei-templates/exposures/ -silent -o nuclei-secrets.txt 2>/dev/null || touch nuclei-secrets.txt

# 5. Nuclei CVE
echo "[5/9] Nuclei CVE..."
cat live.txt | nuclei -severity medium,high,critical -silent -o nuclei-cve.txt 2>/dev/null || touch nuclei-cve.txt

# 6. Takeover
echo "[6/9] Subzy..."
timeout 120 cat subdomains.txt | subzy run -o takeover.txt

# 7. GF patterns
echo "[7/9] GF vuln URLs..."
cat urls.txt | gf xss > gf-xss.txt 2>/dev/null || touch gf-xss.txt
cat urls.txt | gf lfi > gf-lfi.txt 2>/dev/null || touch gf-lfi.txt
cat urls.txt | gf sqli > gf-sqli.txt 2>/dev/null || touch gf-sqli.txt

# 8. Bxss (si XSS candidates)
if [ -s gf-xss.txt ]; then
  echo "[8/9] Bxss auto-XSS..."
  timeout 300 cat gf-xss.txt | bxss -o bxss-results.txt 2>/dev/null || touch bxss-results.txt
else
  touch bxss-results.txt
fi

# 9. Directory bruteforce
echo "[9/9] Feroxbuster ($WORDLIST)..."
timeout 600 cat live.txt | feroxbuster --stdin -w "$WORDLIST" -x js,html,php -o ferox.txt 2>/dev/null || echo "Ferox timeout OK"

cat << EOF > RAPPORT-BUGBOUNTY.txt
Recon $TARGET - $(date)

FICHIERS GÉNÉRÉS :

subdomains.txt          - Tous sous-domaines
live.txt               - Pages web actives (200/3xx/403)  
urls.txt               - URLs crawlées
nuclei-secrets.txt     - Secrets exposés (API keys)
nuclei-cve.txt         - CVE medium+
takeover.txt           - Subdomain takeover
gf-xss.txt             - Params XSS
gf-lfi.txt             - Params LFI
gf-sqli.txt            - Params SQLi
bxss-results.txt       - Tests XSS auto
ferox.txt              - Directory bruteforce

PRIORITÉ : nuclei-secrets.txt > takeover.txt > gf-xss.txt
EOF
