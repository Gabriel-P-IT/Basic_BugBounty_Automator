#!/bin/bash

################################################################################
# Bug Bounty Automator v2.3
#
# Usage: ./bb-automator.sh example.com [proxy_url]
################################################################################

set -euo pipefail

TARGET="${1:?Erreur: target requis}"
PROXY="${2:-}"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
OUTPUT_DIR="bb-${TARGET}-${TIMESTAMP}"
BASE_DIR="$(pwd)"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

LOG_FILE="execution.log"
: > "$LOG_FILE"
PHASE_START_TIME=0

TIMEOUT_KATANA=600
TIMEOUT_NUCLEI_CVE=600
TIMEOUT_NUCLEI_SECRETS=300
TIMEOUT_SUBZY=300
TIMEOUT_FEROX=300

HTTPX_RATE=100
NUCLEI_RATE=100
FFUF_RATE=50

SUBFINDER_PROVIDERS="${SUBFINDER_PROVIDERS:-chaos,shodan,censys}"

GF_MODE="default"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    local color

    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    color="$NC"

    case "$level" in
        INFO)  color="$BLUE" ;;
        OK)    color="$GREEN" ;;
        WARN)  color="$YELLOW" ;;
        ERR)   color="$RED" ;;
    esac

    printf "${color}[${timestamp}] [${level}]${NC} ${message}\n" | tee -a "$LOG_FILE"
}

log_banner() {
    echo "" | tee -a "$LOG_FILE"
    printf "════════════════════════════════════════════════════════\n" | tee -a "$LOG_FILE"
    printf "  %s\n" "$1" | tee -a "$LOG_FILE"
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
        cd "$BASE_DIR" 2>/dev/null || true
        tar -czf "${OUTPUT_DIR}.tar.gz" "$OUTPUT_DIR" 2>/dev/null || true
        cd "$OUTPUT_DIR" 2>/dev/null || true
        log OK "Archive: ${BASE_DIR}/${OUTPUT_DIR}.tar.gz"
    else
        log WARN "Script interrompu (code $exit_code)"
    fi
}
trap cleanup EXIT

choose_gf_mode() {
    log_banner "CONFIGURATION GF"

    echo "  [1] Default (utilise tes patterns deja presents)"
    echo "  [2] Custom (cree/force patterns via gf -save)"
    echo "  [3] Skip (pas de GF)"
    echo ""
    read -r -p "Choix (1-3): " gf_choice

    case "${gf_choice:-1}" in
        1) GF_MODE="default" ;;
        2) GF_MODE="custom" ;;
        3) GF_MODE="skip" ;;
        *) GF_MODE="default" ;;
    esac

    log OK "GF_MODE=${GF_MODE}"
}

validate_input() {
    log_banner "VALIDATION ENTREES"

    if [[ "$TARGET" =~ ^(localhost|127\.0\.0\.1)(:[0-9]+)?$ ]]; then
        log OK "Cible localhost/IP detectee: $TARGET"
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

    if [[ "$TARGET" =~ ^(localhost|127\.0\.0\.1)(:[0-9]+)?$ ]]; then
        log OK "Localhost detecte -> DNS/Ping skip"
        return 0
    fi

    if ! host "$TARGET" >/dev/null 2>&1; then
        die "Resolution DNS echouee: $TARGET"
    fi
    local ip
    ip=$(host "$TARGET" 2>/dev/null | head -1 | awk '{print $NF}')
    log OK "DNS: $ip"

    if ping -c 1 -W 2 "$TARGET" >/dev/null 2>&1; then
        log OK "ICMP OK"
    else
        log WARN "ICMP timeout"
    fi
}

check_tools() {
    log_banner "VERIFICATION DEPENDANCES"

    local tools=("subfinder" "httpx" "katana" "nuclei" "subzy" "ffuf" "feroxbuster" "jq" "curl" "grep")
    local missing=()

    if [ "$GF_MODE" != "skip" ]; then
        tools+=("gf")
    fi

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

    [ -z "$ferox_wordlist" ] && die "Wordlist dirbuster introuvable. Installe seclists."
    log OK "Feroxbuster wordlist detectee"
    echo "$ferox_wordlist"
}

setup_nuclei() {
    log_banner "CONFIGURATION NUCLEI"

    nuclei -update-templates >/dev/null 2>&1 || log WARN "Update templates echouee"

    local templates_path="$HOME/.nuclei-templates"
    [ -d "$templates_path" ] || die "Templates nuclei introuvables apres update"
    log OK "Templates detectes"
    echo "$templates_path"
}

# Subfinder - Enumeration sous-domaines
run_subfinder() {
    log_banner "PHASE 1: SUBFINDER"

    if [[ "$TARGET" =~ ^(localhost|127\.0\.0\.1)(:[0-9]+)?$ ]]; then
        log INFO "Localhost -> Subfinder skip"
        echo "$TARGET" > subdomains.txt
        log OK "Subfinder: localhost force"
        return 0
    fi

    local cmd
    cmd="subfinder -d $TARGET -all -silent -t 100"
    if [ -n "${SUBFINDER_PROVIDERS:-}" ]; then
        cmd="$cmd -providers $SUBFINDER_PROVIDERS"
    fi
    [ -n "$PROXY" ] && cmd="$cmd -proxy $PROXY"

    if eval "$cmd -o subdomains.txt" 2>/dev/null; then
        local count
        count=$(wc -l < subdomains.txt 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            log OK "Subfinder: $count subdomaines"
            log_timing "Subfinder"
            return 0
        fi
    fi

    log WARN "Subfinder fallback -> $TARGET"
    echo "$TARGET" > subdomains.txt
    log_timing "Subfinder"
}

# HTTPX - Validation HTTP
run_httpx() {
    log_banner "PHASE 2: HTTPX"

    [ -s subdomains.txt ] || echo "$TARGET" > subdomains.txt

    local cmd
    cmd="cat subdomains.txt | httpx -silent -mc 200,301,302 -timeout 5 -rate-limit $HTTPX_RATE -o live-raw.txt"
    [ -n "$PROXY" ] && cmd="$cmd -http-proxy $PROXY"

    eval "$cmd" || die "HTTPX echoue"

    local count
    count=$(wc -l < live-raw.txt 2>/dev/null || echo 0)
    log OK "HTTPX: $count hotes actifs"

    parse_urls "live-raw.txt" "live.txt"
    log_timing "HTTPX"
}

parse_urls() {
    local input="$1"
    local output="$2"

    if [ ! -s "$input" ]; then
        log WARN "$input vide -> $output vide"
        : > "$output"
        return 0
    fi

    grep -oE 'https?://[^[:space:]]+' "$input" 2>/dev/null | sort -u > "$output" 2>/dev/null || : > "$output"

    local count
    count=$(wc -l < "$output" 2>/dev/null || echo 0)
    log INFO "Parse: $count URLs -> $output"
}

# Katana - Web crawling
run_katana() {
    log_banner "PHASE 3: KATANA"

    if [ ! -s live.txt ]; then
        log WARN "live.txt vide"
        : > urls.txt
        return 0
    fi

    local cmd
    cmd="timeout $TIMEOUT_KATANA cat live.txt | katana -silent -depth 3 -timeout 10 -c 50 -rl 100 -js-crawl -o urls.txt"
    [ -n "$PROXY" ] && cmd="timeout $TIMEOUT_KATANA cat live.txt | katana -silent -depth 3 -timeout 10 -c 50 -rl 100 -js-crawl -proxy $PROXY -o urls.txt"

    eval "$cmd" 2>/dev/null || true

    local count
    count=$(wc -l < urls.txt 2>/dev/null || echo 0)
    log OK "Katana: $count URLs"
    log_timing "Katana"
}

# Nuclei - Scans
run_nuclei() {
    log_banner "PHASE 4: NUCLEI"

    if [ ! -s live.txt ]; then
        log WARN "live.txt vide"
        : > nuclei-cve.txt
        : > nuclei-secrets.txt
        return 0
    fi

    local cmd

    log INFO "Scan CVE..."
    cmd="cat live.txt | timeout $TIMEOUT_NUCLEI_CVE nuclei -rate-limit $NUCLEI_RATE -severity medium,high,critical -silent -o nuclei-cve.txt"
    [ -n "$PROXY" ] && cmd="cat live.txt | timeout $TIMEOUT_NUCLEI_CVE nuclei -rate-limit $NUCLEI_RATE -severity medium,high,critical -proxy $PROXY -silent -o nuclei-cve.txt"
    eval "$cmd" 2>/dev/null || true

    log INFO "Scan secrets..."
    cmd="cat live.txt | timeout $TIMEOUT_NUCLEI_SECRETS nuclei -rate-limit $NUCLEI_RATE -tags token,exposure,default-login -silent -o nuclei-secrets.txt"
    [ -n "$PROXY" ] && cmd="cat live.txt | timeout $TIMEOUT_NUCLEI_SECRETS nuclei -rate-limit $NUCLEI_RATE -tags token,exposure,default-login -proxy $PROXY -silent -o nuclei-secrets.txt"
    eval "$cmd" 2>/dev/null || true

    log OK "Nuclei CVE: $(wc -l < nuclei-cve.txt 2>/dev/null || echo 0)"
    log OK "Nuclei secrets: $(wc -l < nuclei-secrets.txt 2>/dev/null || echo 0)"
    log_timing "Nuclei"
}

# Subzy - Takeover
run_subzy() {
    log_banner "PHASE 5: SUBZY"

    if [ ! -s subdomains.txt ]; then
        log WARN "subdomains.txt vide"
        : > takeover.txt
        return 0
    fi

    timeout "$TIMEOUT_SUBZY" subzy check -l subdomains.txt -o takeover.json 2>/dev/null || true

    if [ -s takeover.json ]; then
        jq -r '.. | objects | select(has(\"vulnerable\") and .vulnerable==true) | .domain? // empty' takeover.json 2>/dev/null \
            | sed '/^null$/d' | sort -u > takeover.txt 2>/dev/null || : > takeover.txt
    else
        : > takeover.txt
    fi

    log OK "Takeovers: $(wc -l < takeover.txt 2>/dev/null || echo 0)"
    log_timing "Subzy"
}

# GF - Pattern matching (default/custom/skip)
run_gf() {
    log_banner "PHASE 6: GF PATTERNS"

    if [ "$GF_MODE" = "skip" ]; then
        log INFO "GF skip"
        : > gf-xss.txt
        : > gf-lfi.txt
        : > gf-sqli.txt
        : > gf-ssti.txt
        log_timing "GF"
        return 0
    fi

    if [ ! -s urls.txt ]; then
        log WARN "urls.txt vide"
        : > gf-xss.txt
        : > gf-lfi.txt
        : > gf-sqli.txt
        : > gf-ssti.txt
        return 0
    fi

    mkdir -p "$HOME/.gf"

    if [ "$GF_MODE" = "custom" ]; then
        gf -save xss  -aEi '(\?|&)(q|s|search|query|redirect|next|return|url|callback|dest|path|continue|data)=' >/dev/null 2>&1 || true
        gf -save lfi  -aEi '(\?|&)(file|path|page|include|inc|template|load|lang|doc)='                       >/dev/null 2>&1 || true
        gf -save sqli -aEi '(\?|&)(id|uid|user|userid|account|item|pid|cat)='                                 >/dev/null 2>&1 || true
        gf -save ssti -aEi '(\{\{|\{%|<%|%>|\$\{|#\{)'                                                         >/dev/null 2>&1 || true
        log OK "GF custom patterns enregistres"
    else
        log INFO "GF default patterns"
    fi

    local patterns=("xss" "lfi" "sqli" "ssti")
    for pattern in "${patterns[@]}"; do
        if gf "$pattern" urls.txt > "gf-${pattern}.txt" 2>/dev/null; then
            log OK "GF $pattern: $(wc -l < "gf-${pattern}.txt" 2>/dev/null || echo 0)"
        else
            : > "gf-${pattern}.txt"
            log WARN "GF $pattern: 0"
        fi
    done

    log_timing "GF"
}

# FFUF - XSS fuzzing
run_ffuf_xss() {
    log_banner "PHASE 7: FFUF XSS"

    local xss_wordlist="$1"

    if [ ! -s gf-xss.txt ] || [ ! -s "$xss_wordlist" ]; then
        log WARN "FFUF XSS skip"
        : > ffuf-xss.json
        : > ffuf-xss.txt
        return 0
    fi

    local count=0
    while IFS= read -r url; do
        if [[ "$url" =~ \?([^=]+)= ]]; then
            local param="${BASH_REMATCH[1]}"
            local base="${url%\?*}"
            local fuzz_url="${base}?${param}=FUZZ"

            timeout 60 ffuf -u "$fuzz_url" -w "$xss_wordlist" \
                -mc 200,301,302,403 -rate "$FFUF_RATE" \
                -o "ffuf-${count}.json" 2>/dev/null || true

            ((count++))
            log INFO "FFUF XSS: ${count} requetes lancees"
        fi
    done < gf-xss.txt

    cat ffuf-*.json > ffuf-xss.json 2>/dev/null || : > ffuf-xss.json
    log OK "FFUF XSS: $count URLs testees"
    log_timing "FFUF"
}

# Feroxbuster - Dir fuzzing
run_feroxbuster() {
    log_banner "PHASE 8: FEROXBUSTER"

    if [ ! -s live.txt ]; then
        log WARN "live.txt vide"
        : > ferox.txt
        return 0
    fi

    local wordlist="$1"

    timeout "$TIMEOUT_FEROX" cat live.txt | \
        feroxbuster --stdin -w "$wordlist" -x js,html,php,txt,json \
        --rate-limit "$FFUF_RATE" -o ferox.txt 2>/dev/null || true

    [ -f ferox.txt ] || : > ferox.txt
    log OK "Feroxbuster: $(wc -l < ferox.txt 2>/dev/null || echo 0)"
    log_timing "Feroxbuster"
}

run_parallel_phase_1() {
    log_banner "ENUMERATION (parallele)"
    run_subfinder &
    local pid_subfinder=$!
    wait $pid_subfinder

    run_httpx &
    wait $!
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
  CVE/Vulnerabilites:  $([ -s nuclei-cve.txt ] && wc -l < nuclei-cve.txt || echo "0")
  Secrets/Expositions: $([ -s nuclei-secrets.txt ] && wc -l < nuclei-secrets.txt || echo "0")
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
EOF

    log OK "Rapport genere"
}

main() {
    local START_TIME
    START_TIME=$(date +%s)

    clear
    printf "================================================================================\n"
    printf "Bug Bounty Automator v2.3 - PRODUCTION\n"
    printf "================================================================================\n\n"

    log INFO "Repertoire: $(pwd)"

    validate_input
    check_connectivity

    choose_gf_mode
    check_tools

    local ferox_wordlist
    ferox_wordlist=$(check_wordlists)

    local templates_path
    templates_path=$(setup_nuclei)

    log_banner "CONFIGURATION WORDLIST XSS"
    echo "  [1] SecLists XSS (Jhaddix)"
    echo "  [2] Personnalise (chemin)"
    echo "  [3] Skip FFUF"
    echo ""
    read -r -p "Choix (1-3): " xss_choice

    local xss_wordlist=""
    case "${xss_choice:-3}" in
        1) xss_wordlist="/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt" ;;
        2) read -r -p "Chemin: " xss_wordlist ;;
        *) xss_wordlist="" ;;
    esac

    if [ -n "$xss_wordlist" ] && [ ! -f "$xss_wordlist" ]; then
        log WARN "Wordlist XSS introuvable -> FFUF skip"
        xss_wordlist=""
    fi

    log_banner "EXECUTION"

    run_parallel_phase_1
    run_parallel_phase_2 "$templates_path"

    if [ -n "$xss_wordlist" ]; then
        run_parallel_phase_3 "$xss_wordlist" "$ferox_wordlist"
    else
        run_gf &
        local pid_gf=$!
        run_feroxbuster "$ferox_wordlist" &
        local pid_ferox=$!
        wait $pid_gf $pid_ferox
        : > ffuf-xss.json
    fi

    generate_report

    local TOTAL_TIME=$(( $(date +%s) - START_TIME ))
    log_banner "COMPLETION"
    log OK "Fichiers: $(ls -1 | wc -l)"
    log OK "Taille: $(du -sh . | cut -f1)"
    log OK "Temps total: ${TOTAL_TIME}s"
    log OK "Rapport: RAPPORT-BUGBOUNTY.txt"
}

main "$@"
