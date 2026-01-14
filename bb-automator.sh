#!/bin/bash

################################################################################
# Bug Bounty Automator v2.2
# 
#
# Usage: ./bb-automator.sh example.com [proxy_url]
################################################################################

set -euo pipefail

TARGET="${1:?Erreur: target requis}"
PROXY="${2:-}"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
OUTPUT_DIR="bb-${TARGET}-${TIMESTAMP}"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

LOG_FILE="execution.log"
: > "$LOG_FILE"
PHASE_START_TIME=0


TIMEOUT_KATANA=300
TIMEOUT_FEROX=600
TIMEOUT_FFUF=180

HTTPX_RATE=50
NUCLEI_RATE=50
FFUF_RATE=100

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local color=""
    
    case "$level" in
        INFO)  color="$BLUE" ;;
        OK)    color="$GREEN" ;;
        WARN)  color="$YELLOW" ;;
        ERR)   color="$RED" ;;
        *)     color="$NC" ;;
    esac
    
    printf "${color}[${timestamp}] [${level}]${NC} ${message}\n" | tee -a "$LOG_FILE"
}

log_banner() {
    echo "" | tee -a "$LOG_FILE"
    printf "════════════════════════════════════════════════════════\n" | tee -a "$LOG_FILE"
    printf "  $1\n" | tee -a "$LOG_FILE"
    printf "════════════════════════════════════════════════════════\n" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    PHASE_START_TIME=$(date +%s)
}

log_timing() {
    local phase="$1"
    local elapsed=$(( $(date +%s) - PHASE_START_TIME ))
    log OK "$phase - Temps: ${elapsed}s"
}

die() {
    log ERR "FATAL: $*"
    exit 1
}

cleanup() {
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        log OK "Archivage en cours..."
        tar -czf "${OUTPUT_DIR}.tar.gz" "$OUTPUT_DIR" 2>/dev/null || true
        log OK "Archive: ${OUTPUT_DIR}.tar.gz"
    else
        log WARN "Script interrompu (code $exit_code)"
    fi
}
trap cleanup EXIT

validate_input() {
    log_banner "VALIDATION ENTREES"
    
    # Support localhost/IP:port pour test
    if [[ "$TARGET" =~ ^(localhost|127\.0\.0\.1)(:[0-9]+)?$ ]]; then
        log OK "Cible localhost/IP détectée: $TARGET"
        return 0
    fi
    
    TARGET=$(echo "$TARGET" | sed 's|^https\?://||;s|^www\.||;s|/$||')
    log INFO "Cible: $TARGET"
    
    if ! [[ "$TARGET" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        die "Format domaine invalide: $TARGET"
    fi
}

check_connectivity() {
    log_banner "CONNECTIVITE ET DNS"
    
    # Skip DNS pour localhost/IP
    if [[ "$TARGET" =~ ^(localhost|127\.0\.0\.1)(:[0-9]+)?$ ]]; then
        log OK "Localhost: DNS skip"
        TARGET_IP="127.0.0.1${TARGET#127.0.0.1}"
    else
        if ! host "$TARGET" >/dev/null 2>&1; then
            die "Resolution DNS echouee: $TARGET"
        fi
        local ip=$(host "$TARGET" 2>/dev/null | head -1 | awk '{print $NF}')
        log OK "DNS: $ip"
        TARGET_IP="$ip"
    fi
    
    # Ping seulement si pas localhost
    if ! [[ "$TARGET_IP" =~ ^127\. ]]; then
        if ping -c 1 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
            log OK "ICMP OK"
        else
            log WARN "ICMP timeout (normal WAF)"
        fi
    else
        log OK "Localhost connectivité OK"
    fi
}

check_tools() {
    log_banner "VERIFICATION DEPENDANCES"
    
    local tools=("subfinder" "httpx" "katana" "nuclei" "subzy" "gf" "ffuf" "feroxbuster" "jq" "curl" "grep")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log OK "$tool OK"
        else
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        die "Outils manquants: ${missing[*]}"
    fi
}

check_wordlists() {
    log_banner "VERIFICATION WORDLISTS"
    
    local ferox_wordlist=""
    for path in \
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" \
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" \
        "/opt/wordlists/dirbuster-medium.txt"; do
        if [ -f "$path" ]; then
            ferox_wordlist="$path"
            break
        fi
    done
    
    if [ -z "$ferox_wordlist" ]; then
        die "Wordlist dirbuster introuvable. Installe seclists."
    fi
    
    log OK "Feroxbuster wordlist detectee"
    echo "$ferox_wordlist"
}

setup_nuclei() {
    log_banner "CONFIGURATION NUCLEI"
    
    if ! nuclei -update-templates >/dev/null 2>&1; then
        log WARN "Update templates echouee"
    else
        log OK "Templates mises a jour"
    fi
    
    local templates_path="$HOME/.nuclei-templates"
    if [ -d "$templates_path" ]; then
        log OK "Templates detectes"
        echo "$templates_path"
    else
        die "Templates nuclei introuvables apres update"
    fi
}

# Subfinder - Enumeration sous-domaines
run_subfinder() {
    log_banner "PHASE 1: SUBFINDER"
    
    local cmd="subfinder -d $TARGET -silent"
    [ -n "$PROXY" ] && cmd="$cmd -proxy $PROXY"
    
    if eval "$cmd -o subdomains.txt"; then
        local count=$(wc -l < subdomains.txt)
        if [ "$count" -gt 0 ]; then
            log OK "Subfinder: $count subdomaines"
            log_timing "Subfinder"
            return 0
        else
            log WARN "Subfinder: aucun resultat"
            return 1
        fi
    else
        log ERR "Subfinder echoue"
        return 1
    fi
}

# HTTPX - Validation HTTP et resolution
run_httpx() {
    log_banner "PHASE 2: HTTPX"
    
    if [ ! -s subdomains.txt ]; then
        log WARN "subdomains.txt vide"
        echo "$TARGET" > subdomains.txt
    fi
    
    local cmd="cat subdomains.txt | httpx -silent -mc 200,301,302 -timeout 5 -rate-limit $HTTPX_RATE -o live-raw.txt"
    [ -n "$PROXY" ] && cmd="$cmd -http-proxy $PROXY"
    
    if eval "$cmd"; then
        local count=$(wc -l < live-raw.txt)
        log OK "HTTPX: $count hotes actifs"
        parse_urls "live-raw.txt" "live.txt"
        log_timing "HTTPX"
        return 0
    else
        log ERR "HTTPX echoue"
        return 1
    fi
}

parse_urls() {
    local input="$1"
    local output="$2"
    
    if [ ! -f "$input" ] || [ ! -s "$input" ]; then
        log WARN "$input vide/absent -> skip"
        touch "$output"
        return 0
    fi
    
    cut -d'[' -f2 "$input" 2>/dev/null | \
    cut -d']' -f1 2>/dev/null | \
    grep '^https\?://' 2>/dev/null | \
    sort -u > "$output" 2>/dev/null
    
    local count=$(wc -l < "$output" 2>/dev/null || echo 0)
    log INFO "Parse: $count URLs propres ($output)"
}



# Katana - Web crawling
run_katana() {
    log_banner "PHASE 3: KATANA"
    
    if [ ! -s live.txt ]; then
        log WARN "live.txt vide"
        touch urls.txt
        return 0
    fi
    
    local cmd="timeout $TIMEOUT_KATANA cat live.txt | katana -silent -depth 2 -timeout 5"
    [ -n "$PROXY" ] && cmd="$cmd -proxy $PROXY"
    cmd="$cmd -o urls.txt"
    
    if eval "$cmd" 2>/dev/null || true; then
        local count=$(wc -l < urls.txt)
        if [ "$count" -gt 0 ]; then
            log OK "Katana: $count URLs"
        else
            log WARN "Katana: aucun resultat"
        fi
        log_timing "Katana"
        return 0
    else
        log WARN "Katana timeout"
        return 0
    fi
}

# Nuclei - Detection vulnerabilites et secrets
run_nuclei() {
    log_banner "PHASE 4: NUCLEI"
    
    if [ ! -s live.txt ]; then
        log WARN "live.txt vide"
        touch nuclei-cve.json nuclei-secrets.json
        return 0
    fi
    
    log INFO "Scan CVE..."
    local cmd="cat live.txt | timeout 600 nuclei -rate-limit $NUCLEI_RATE -severity medium,high,critical -silent"
    [ -n "$PROXY" ] && cmd="$cmd -proxy $PROXY"
    cmd="$cmd -o nuclei-cve.json"
    
    if eval "$cmd" 2>/dev/null || true; then
        local count=$(wc -l < nuclei-cve.json)
        log OK "CVE detectes: $count"
    else
        log WARN "Nuclei CVE timeout"
        touch nuclei-cve.json
    fi
    
    log INFO "Scan secrets..."
    cmd="cat live.txt | timeout 300 nuclei -rate-limit $NUCLEI_RATE -tags exposure,secret,creds -silent"
    [ -n "$PROXY" ] && cmd="$cmd -proxy $PROXY"
    cmd="$cmd -o nuclei-secrets.json"
    
    if eval "$cmd" 2>/dev/null || true; then
        local count=$(wc -l < nuclei-secrets.json)
        log OK "Secrets detectes: $count"
    else
        log WARN "Nuclei secrets timeout"
        touch nuclei-secrets.json
    fi
    
    log_timing "Nuclei"
}

# Subzy - Detection takeover sous-domaines
run_subzy() {
    log_banner "PHASE 5: SUBZY"
    
    if [ ! -s subdomains.txt ]; then
        log WARN "subdomains.txt vide"
        touch takeover.txt
        return 0
    fi
    
    if timeout 300 subzy check -l subdomains.txt -o takeover.json 2>/dev/null || true; then
        local count=$(jq 'length' takeover.json 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            jq -r '.domains[]? | select(.vulnerable==true) | .domain' takeover.json > takeover.txt 2>/dev/null || true
            local vuln_count=$(wc -l < takeover.txt 2>/dev/null || echo 0)
            log OK "Takeovers detectes: $vuln_count"
        else
            log INFO "Aucun takeover"
            touch takeover.txt
        fi
    else
        log WARN "Subzy timeout"
        touch takeover.txt
    fi
    
    log_timing "Subzy"
}

# GF - Pattern matching sur URLs
run_gf() {
    log_banner "PHASE 6: GF PATTERNS"
    
    if [ ! -s urls.txt ]; then
        log WARN "urls.txt vide"
        touch gf-xss.txt gf-lfi.txt gf-sqli.txt gf-ssti.txt
        return 0
    fi
    
    if ! gf -list 2>/dev/null | grep -q xss; then
        log WARN "Patterns GF manquants"
        touch gf-xss.txt gf-lfi.txt gf-sqli.txt gf-ssti.txt
        return 0
    fi
    
    local patterns=("xss" "lfi" "sqli" "ssti")
    for pattern in "${patterns[@]}"; do
        if cat urls.txt | gf "$pattern" > "gf-${pattern}.txt" 2>/dev/null || true; then
            local count=$(wc -l < "gf-${pattern}.txt")
            log OK "GF $pattern: $count params"
        else
            touch "gf-${pattern}.txt"
        fi
    done
    
    log_timing "GF"
}

# FFUF - Fuzzing XSS avec payloads
run_ffuf_xss() {
    log_banner "PHASE 7: FFUF XSS"
    
    if [ ! -s gf-xss.txt ] || [ ! -s "$1" ]; then
        log WARN "Pas de params XSS ou wordlist absente"
        touch ffuf-xss.json ffuf-xss.txt
        return 0
    fi
    
    local xss_wordlist="$1"
    local count=0
    
    while IFS= read -r url; do
        # Extraire le paramètre (ex: /search?q=FUZZ)
        if [[ "$url" =~ \?([^=]+)= ]]; then
            local param="${BASH_REMATCH[1]}"
            local base="${url%\?*}"
            local fuzz_url="${base}?${param}=FUZZ"
            
            log INFO "Fuzzing: $fuzz_url"
            timeout 60 ffuf -u "$fuzz_url" -w "$xss_wordlist" \
                -mc 200,301,302,403 -rate 50 \
                -o "ffuf-${count}.json" 2>/dev/null || true
            
            ((count++))
        fi
    done < gf-xss.txt
    
    # Merger résultats
    cat ffuf-*.json > ffuf-xss.json 2>/dev/null || touch ffuf-xss.json
    log OK "FFUF XSS: $count URLs testées"
    log_timing "FFUF"
}

# Feroxbuster - Directory fuzzing
run_feroxbuster() {
    log_banner "PHASE 8: FEROXBUSTER"
    
    if [ ! -s live.txt ]; then
        log WARN "live.txt vide"
        touch ferox.txt
        return 0
    fi
    
    local wordlist="$1"
    
    if timeout $TIMEOUT_FEROX cat live.txt | \
        feroxbuster --stdin -w "$wordlist" -x js,html,php,txt,json \
        --rate-limit $FFUF_RATE -o ferox.txt 2>/dev/null || true; then
        [ -f ferox.txt ] || touch ferox.txt
        
        local count=$(wc -l < ferox.txt 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            log OK "Feroxbuster: $count endpoints"
        else
            log INFO "Aucun endpoint trouvé"
        fi
    else
        log WARN "Feroxbuster timeout"
        touch ferox.txt 
    fi
    
    log_timing "Feroxbuster"
}


run_parallel_phase_1() {
    log_banner "ENUMERATION (parallele)"
    
    run_subfinder &
    local pid_subfinder=$!
    
    wait $pid_subfinder
    
    if [ -s subdomains.txt ]; then
        run_httpx &
        wait $!
    fi
}

run_parallel_phase_2() {
    log_banner "CRAWLING ET ANALYSE (parallele)"
    
    run_katana &
    local pid_katana=$!
    
    run_nuclei "$1" &
    local pid_nuclei=$!
    
    run_subzy &
    local pid_subzy=$!
    
    wait $pid_katana $pid_nuclei $pid_subzy
}

run_parallel_phase_3() {
    log_banner "FUZZING (parallele)"
    
    run_gf &
    local pid_gf=$!
    
    run_ffuf_xss "$1" &
    local pid_ffuf=$!
    
    run_feroxbuster "$2" &
    local pid_ferox=$!
    
    wait $pid_gf $pid_ffuf $pid_ferox
}

generate_report() {
    log_banner "GENERATION RAPPORT"
    
    local report_file="RAPPORT-BUGBOUNTY.txt"
    
    cat > "$report_file" << EOF
================================================================================
                      BUG BOUNTY RECON REPORT
================================================================================

Cible: $TARGET
Date: $(date '+%Y-%m-%d %H:%M:%S')

================================================================================
RESULTATS NUMERIQUES
================================================================================

Enumeration:
  Sous-domaines:       $([ -s subdomains.txt ] && wc -l < subdomains.txt || echo "0")
  Hotes actifs:        $([ -s live.txt ] && wc -l < live.txt || echo "0")
  URLs crawlees:       $([ -s urls.txt ] && wc -l < urls.txt || echo "0")

Securite:
  CVE/Vulnerabilites:  $([ -s nuclei-cve.json ] && wc -l < nuclei-cve.json || echo "0")
  Secrets/Expositions: $([ -s nuclei-secrets.json ] && wc -l < nuclei-secrets.json || echo "0")
  Takeovers:           $([ -s takeover.txt ] && wc -l < takeover.txt || echo "0")

Parametres:
  XSS potentiels:      $([ -s gf-xss.txt ] && wc -l < gf-xss.txt || echo "0")
  LFI potentiels:      $([ -s gf-lfi.txt ] && wc -l < gf-lfi.txt || echo "0")
  SQLi potentiels:     $([ -s gf-sqli.txt ] && wc -l < gf-sqli.txt || echo "0")
  SSTI potentiels:     $([ -s gf-ssti.txt ] && wc -l < gf-ssti.txt || echo "0")

Fuzzing:
  FFUF XSS results:    $([ -s ffuf-xss.json ] && wc -l < ffuf-xss.json || echo "0")
  Repertoires:         $([ -s ferox.txt ] && wc -l < ferox.txt || echo "0")

================================================================================
CRITIQUES A VERIFIER
================================================================================

EOF

    if [ -s takeover.txt ] && [ "$(wc -l < takeover.txt)" -gt 0 ]; then
        echo "TAKEOVERS DETECTES:" >> "$report_file"
        cat takeover.txt | head -10 >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    if [ -s nuclei-secrets.json ] && [ "$(wc -l < nuclei-secrets.json)" -gt 0 ]; then
        echo "SECRETS/EXPOSITIONS:" >> "$report_file"
        jq -r '.extracted // .template // empty' nuclei-secrets.json 2>/dev/null | head -10 >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    if [ -s nuclei-cve.json ] && [ "$(wc -l < nuclei-cve.json)" -gt 0 ]; then
        echo "CVE CRITIQUES:" >> "$report_file"
        jq -r 'select(.severity=="critical") | .template_name' nuclei-cve.json 2>/dev/null | head -10 >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

================================================================================
FICHIERS GENERES
================================================================================

Enumeration:
  subdomains.txt       - Tous les sous-domaines
  live.txt             - Hotes actifs (HTTP 200/301/302/403)
  urls.txt             - URLs crawlees

Securite:
  nuclei-cve.json      - CVE et vulnerabilites detectes
  nuclei-secrets.json  - Secrets et expositions
  takeover.json        - Resultats Subzy
  takeover.txt         - Takeovers confirmes

Parametres:
  gf-xss.txt           - Params XSS potentiels
  gf-lfi.txt           - Params LFI potentiels
  gf-sqli.txt          - Params SQLi potentiels
  gf-ssti.txt          - Params SSTI potentiels

Fuzzing:
  ffuf-xss.json        - Resultats FFUF XSS
  ferox.txt            - Repertoires et fichiers decouvert

Logs:
  execution.log        - Logs d'execution detailles
  RAPPORT-BUGBOUNTY.txt - Ce rapport

================================================================================
EOF

    log OK "Rapport genere"
}

main() {
    local START_TIME=$(date +%s)
    
    clear
    printf "================================================================================\n"
    printf "Bug Bounty Automator v2.2 - PRODUCTION\n"
    printf "================================================================================\n\n"
    
    log INFO "Repertoire: $(pwd)"
    
    validate_input
    check_connectivity
    check_tools
    local ferox_wordlist=$(check_wordlists)
    local templates_path=$(setup_nuclei)
    
    log_banner "CONFIGURATION WORDLIST XSS"
    echo ""
    echo "  [1] SecLists XSS (Jhaddix)"
    echo "  [2] Personnalise (chemin)"
    echo "  [3] Skip FFUF"
    echo ""
    read -p "Choix (1-3): " xss_choice
    
    local xss_wordlist=""
    case "$xss_choice" in
        1)
            xss_wordlist="/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt"
            if [ ! -f "$xss_wordlist" ]; then
                log WARN "Wordlist manquante"
                sudo apt update && sudo apt install -y seclists 2>/dev/null || \
                    log WARN "Installation echouee"
            fi
            ;;
        2)
            read -p "Chemin: " xss_wordlist
            [ ! -f "$xss_wordlist" ] && { log WARN "Fichier absent"; xss_wordlist=""; }
            ;;
        *)
            log WARN "FFUF skip"
            ;;
    esac
    
    if [ -n "$xss_wordlist" ]; then
        log OK "Wordlist XSS selectionnee"
    fi
    
    log_banner "EXECUTION"
    
    run_parallel_phase_1
    run_parallel_phase_2 "$templates_path"
    
    if [ -n "$xss_wordlist" ] && [ -f "$xss_wordlist" ]; then
        run_parallel_phase_3 "$xss_wordlist" "$ferox_wordlist"
    else
        run_gf &
        local pid_gf=$!
        run_feroxbuster "$ferox_wordlist" &
        local pid_ferox=$!
        wait $pid_gf $pid_ferox
        touch ffuf-xss.json
    fi
    
    generate_report
    
    local TOTAL_TIME=$(( $(date +%s) - START_TIME ))
    
    log_banner "COMPLETION"
    log OK "Repertoire: $(pwd)"
    log OK "Fichiers: $(ls -1 | wc -l)"
    log OK "Taille: $(du -sh . | cut -f1)"
    log OK "Temps total: ${TOTAL_TIME}s"
    
    printf "\n"
    log OK "Archive: ../${OUTPUT_DIR}.tar.gz"
    log OK "Rapport: RAPPORT-BUGBOUNTY.txt"
}

main "$@"
