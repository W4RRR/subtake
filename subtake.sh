#!/usr/bin/env bash
#
# SubTake Flow - Advanced Subdomain Takeover Scanner
# https://github.com/W4RRR/subtake
#
# A professional-grade subdomain takeover detection tool
# with intelligent heuristics and low false-positive rates.
#
# Author: .W4R
# License: MIT
#

set -uo pipefail

# Error handling - show where the script failed
trap 'echo -e "\n\033[0;31m[ERROR] Script failed at line $LINENO: $BASH_COMMAND\033[0m" >&2' ERR

# ============================================================================
#                              CONFIGURATION
# ============================================================================

readonly VERSION="2.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly FINGERPRINTS_FILE="${SCRIPT_DIR}/fingerprints.yaml"
readonly DEFAULT_TIMEOUT=10
readonly DEFAULT_THREADS=10
readonly DEFAULT_RESOLVERS="1.1.1.1,8.8.8.8,9.9.9.9"

# ============================================================================
#                              COLORS & STYLING
# ============================================================================

# Check if terminal supports colors
if [[ -t 1 ]] && command -v tput &>/dev/null && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[0;33m'
    readonly BLUE='\033[0;34m'
    readonly MAGENTA='\033[0;35m'
    readonly CYAN='\033[0;36m'
    readonly WHITE='\033[0;37m'
    readonly BOLD='\033[1m'
    readonly DIM='\033[2m'
    readonly RESET='\033[0m'
    readonly BG_RED='\033[41m'
    readonly BG_GREEN='\033[42m'
    readonly BG_YELLOW='\033[43m'
    readonly BG_BLUE='\033[44m'
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' WHITE=''
    readonly BOLD='' DIM='' RESET='' BG_RED='' BG_GREEN='' BG_YELLOW='' BG_BLUE=''
fi

# Status symbols
readonly SYMBOL_OK="${GREEN}✓${RESET}"
readonly SYMBOL_FAIL="${RED}✗${RESET}"
readonly SYMBOL_WARN="${YELLOW}⚠${RESET}"
readonly SYMBOL_INFO="${BLUE}ℹ${RESET}"
readonly SYMBOL_ARROW="${CYAN}→${RESET}"
readonly SYMBOL_SKULL="${RED}☠${RESET}"
readonly SYMBOL_FIRE="${YELLOW}🔥${RESET}"

# ============================================================================
#                              ASCII BANNER
# ============================================================================

show_banner() {
    # Skip banner in silent mode
    [[ "${SILENT:-0}" == "1" ]] && return
    
    echo -e "${CYAN}"
    cat << 'EOF'
   _____       __  ______      __
  / ___/__  __/ /_/_  __/___ _/ /_____
  \__ \/ / / / __ \/ / / __ `/ //_/ _ \
 ___/ / /_/ / /_/ / / / /_/ / ,< /  __/
/____/\__,_/_.___/_/  \__,_/_/|_|\___/
   ________
  / ____/ /___ _      __
 / /_  / / __ \ | /| / /
/ __/ / / /_/ / |/ |/ /
/_/   /_/\____/|__/|__/
                        by .W4R
EOF
    echo -e "${RESET}"
    echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${WHITE}  Advanced Subdomain Takeover Scanner ${DIM}v${VERSION}${RESET}"
    echo -e "${DIM}  Intelligent heuristics • Low false-positives • Fast${RESET}"
    echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo
}

# ============================================================================
#                              LOGGING FUNCTIONS
# ============================================================================

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp="$(date '+%H:%M:%S')"
    
    # Always log to file if RUNLOG is set
    [[ -n "${RUNLOG:-}" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$RUNLOG"
    
    # Silent mode: only show VULN, ERROR and final summary
    if [[ "${SILENT:-0}" == "1" ]]; then
        case "$level" in
            VULN)    echo -e "${DIM}[${timestamp}]${RESET} ${SYMBOL_SKULL} ${BG_RED}${WHITE}${BOLD} VULNERABLE ${RESET} $msg" ;;
            ERROR)   echo -e "${DIM}[${timestamp}]${RESET} ${SYMBOL_FAIL} ${RED}$msg${RESET}" ;;
        esac
        return
    fi
    
    case "$level" in
        INFO)    echo -e "${DIM}[${timestamp}]${RESET} ${SYMBOL_INFO} $msg" ;;
        OK)      echo -e "${DIM}[${timestamp}]${RESET} ${SYMBOL_OK} ${GREEN}$msg${RESET}" ;;
        WARN)    echo -e "${DIM}[${timestamp}]${RESET} ${SYMBOL_WARN} ${YELLOW}$msg${RESET}" ;;
        ERROR)   echo -e "${DIM}[${timestamp}]${RESET} ${SYMBOL_FAIL} ${RED}$msg${RESET}" ;;
        VULN)    echo -e "${DIM}[${timestamp}]${RESET} ${SYMBOL_SKULL} ${BG_RED}${WHITE}${BOLD} VULNERABLE ${RESET} $msg" ;;
        HIGH)    echo -e "${DIM}[${timestamp}]${RESET} ${SYMBOL_FIRE} ${YELLOW}${BOLD}HIGH PROBABILITY${RESET} $msg" ;;
        STEP)    echo -e "\n${BOLD}${BLUE}▶ STEP $msg${RESET}" ;;
        DEBUG)   [[ "${DEBUG:-0}" == "1" ]] && echo -e "${DIM}[${timestamp}] [DEBUG] $msg${RESET}" ;;
        VERBOSE) [[ "${VERBOSE:-0}" == "1" ]] && echo -e "${DIM}[${timestamp}] [VERBOSE] $msg${RESET}" ;;
    esac
}

progress_bar() {
    # Skip in silent mode
    [[ "${SILENT:-0}" == "1" ]] && return
    
    local current="$1"
    local total="$2"
    local width=40
    
    # Avoid division by zero
    [[ $total -eq 0 ]] && total=1
    
    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    local bar_filled="" bar_empty=""
    [[ $filled -gt 0 ]] && bar_filled="$(printf '%*s' "$filled" '' | tr ' ' '#')"
    [[ $empty -gt 0 ]] && bar_empty="$(printf '%*s' "$empty" '' | tr ' ' '-')"
    
    printf "\r${DIM}[${RESET}${GREEN}%s${RESET}${DIM}%s${RESET}${DIM}]${RESET} ${BOLD}%3d%%${RESET} ${DIM}(%d/%d)${RESET}" \
        "$bar_filled" "$bar_empty" "$percent" "$current" "$total"
}

# ============================================================================
#                              DEPENDENCY CHECK
# ============================================================================

declare -A TOOL_URLS=(
    [subfinder]="https://github.com/projectdiscovery/subfinder"
    [amass]="https://github.com/owasp-amass/amass"
    [httpx]="https://github.com/projectdiscovery/httpx"
    [subzy]="https://github.com/PentestPad/subzy"
    [dig]="Part of dnsutils/bind-utils package"
    [curl]="Usually pre-installed or via package manager"
    [jq]="https://stedolan.github.io/jq/"
    [openssl]="Usually pre-installed"
    [parallel]="https://www.gnu.org/software/parallel/"
)

check_dependency() {
    local tool="$1"
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${SYMBOL_OK} ${tool}"
        return 0
    else
        echo -e "  ${SYMBOL_FAIL} ${tool} ${DIM}(${TOOL_URLS[$tool]:-unknown})${RESET}"
        return 1
    fi
}

check_all_dependencies() {
    log INFO "Checking required dependencies..."
    
    local required=(dig curl jq openssl)
    local optional=(subfinder amass httpx subzy parallel)
    local missing_required=0
    local missing_optional=0
    
    # In silent mode, only check without printing
    if [[ "${SILENT:-0}" == "1" ]]; then
        for tool in "${required[@]}"; do
            command -v "$tool" &>/dev/null || missing_required=$((missing_required + 1))
        done
        for tool in "${optional[@]}"; do
            command -v "$tool" &>/dev/null || missing_optional=$((missing_optional + 1))
        done
    else
        echo
        echo -e "${BOLD}Required:${RESET}"
        for tool in "${required[@]}"; do
            check_dependency "$tool" || missing_required=$((missing_required + 1))
        done
        
        echo
        echo -e "${BOLD}Optional (enhanced functionality):${RESET}"
        for tool in "${optional[@]}"; do
            check_dependency "$tool" || missing_optional=$((missing_optional + 1))
        done
        echo
    fi
    
    if [[ $missing_required -gt 0 ]]; then
        log ERROR "Missing $missing_required required dependencies. Please install them first."
        exit 1
    fi
    
    if [[ $missing_optional -gt 0 ]]; then
        log WARN "Missing $missing_optional optional tools. Some features will be limited."
    fi
}

# ============================================================================
#                              FINGERPRINTS DATABASE
# ============================================================================

# Load fingerprints from external file or use built-in defaults
declare -A FINGERPRINTS
declare -A PROVIDER_CNAMES

load_fingerprints() {
    if [[ -f "$FINGERPRINTS_FILE" ]]; then
        log INFO "Loading fingerprints from ${FINGERPRINTS_FILE}"
        # Parse YAML fingerprints file
        while IFS= read -r line; do
            if [[ "$line" =~ ^[[:space:]]*-[[:space:]]*cname:[[:space:]]*\"(.+)\" ]]; then
                current_cname="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ ^[[:space:]]*provider:[[:space:]]*\"(.+)\" ]]; then
                PROVIDER_CNAMES["$current_cname"]="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ ^[[:space:]]*fingerprint:[[:space:]]*\"(.+)\" ]]; then
                FINGERPRINTS["$current_cname"]="${BASH_REMATCH[1]}"
            fi
        done < "$FINGERPRINTS_FILE"
    else
        log WARN "Fingerprints file not found, using built-in defaults"
        load_builtin_fingerprints
    fi
    
    log OK "Loaded ${#FINGERPRINTS[@]} fingerprints"
}

load_builtin_fingerprints() {
    # AWS Services
    PROVIDER_CNAMES["s3.amazonaws.com"]="AWS S3"
    FINGERPRINTS["s3.amazonaws.com"]="NoSuchBucket|The specified bucket does not exist"
    
    PROVIDER_CNAMES["elasticbeanstalk.com"]="AWS Elastic Beanstalk"
    FINGERPRINTS["elasticbeanstalk.com"]="NXDOMAIN"
    
    PROVIDER_CNAMES["cloudfront.net"]="AWS CloudFront"
    FINGERPRINTS["cloudfront.net"]="The request could not be satisfied|Bad Request"
    
    # Azure Services
    PROVIDER_CNAMES["azurewebsites.net"]="Azure Web Apps"
    FINGERPRINTS["azurewebsites.net"]="404 Web Site not found"
    
    PROVIDER_CNAMES["cloudapp.azure.com"]="Azure Cloud App"
    FINGERPRINTS["cloudapp.azure.com"]="NXDOMAIN"
    
    PROVIDER_CNAMES["blob.core.windows.net"]="Azure Blob Storage"
    FINGERPRINTS["blob.core.windows.net"]="The specified resource does not exist"
    
    PROVIDER_CNAMES["azureedge.net"]="Azure CDN"
    FINGERPRINTS["azureedge.net"]="404 Not Found"
    
    PROVIDER_CNAMES["trafficmanager.net"]="Azure Traffic Manager"
    FINGERPRINTS["trafficmanager.net"]="NXDOMAIN"
    
    # Google Cloud
    PROVIDER_CNAMES["storage.googleapis.com"]="Google Cloud Storage"
    FINGERPRINTS["storage.googleapis.com"]="The specified bucket does not exist"
    
    PROVIDER_CNAMES["appspot.com"]="Google App Engine"
    FINGERPRINTS["appspot.com"]="Error: Not Found"
    
    # GitHub Pages
    PROVIDER_CNAMES["github.io"]="GitHub Pages"
    FINGERPRINTS["github.io"]="There isn't a GitHub Pages site here"
    
    PROVIDER_CNAMES["githubusercontent.com"]="GitHub"
    FINGERPRINTS["githubusercontent.com"]="404: Not Found"
    
    # Heroku
    PROVIDER_CNAMES["herokuapp.com"]="Heroku"
    FINGERPRINTS["herokuapp.com"]="No such app|there is no app configured"
    
    PROVIDER_CNAMES["herokudns.com"]="Heroku DNS"
    FINGERPRINTS["herokudns.com"]="No such app"
    
    # Netlify
    PROVIDER_CNAMES["netlify.app"]="Netlify"
    FINGERPRINTS["netlify.app"]="Not Found - Request ID"
    
    PROVIDER_CNAMES["netlify.com"]="Netlify"
    FINGERPRINTS["netlify.com"]="Not Found"
    
    # Vercel
    PROVIDER_CNAMES["vercel.app"]="Vercel"
    FINGERPRINTS["vercel.app"]="The deployment could not be found"
    
    PROVIDER_CNAMES["now.sh"]="Vercel (Now)"
    FINGERPRINTS["now.sh"]="The deployment could not be found"
    
    # Shopify
    PROVIDER_CNAMES["myshopify.com"]="Shopify"
    FINGERPRINTS["myshopify.com"]="Sorry, this shop is currently unavailable"
    
    # Tumblr
    PROVIDER_CNAMES["tumblr.com"]="Tumblr"
    FINGERPRINTS["tumblr.com"]="There's nothing here|Whatever you were looking for doesn't currently exist"
    
    # Ghost
    PROVIDER_CNAMES["ghost.io"]="Ghost"
    FINGERPRINTS["ghost.io"]="The thing you were looking for is no longer here"
    
    # Surge
    PROVIDER_CNAMES["surge.sh"]="Surge.sh"
    FINGERPRINTS["surge.sh"]="project not found"
    
    # Pantheon
    PROVIDER_CNAMES["pantheonsite.io"]="Pantheon"
    FINGERPRINTS["pantheonsite.io"]="The gods are wise|404 Unknown Site"
    
    # Fastly
    PROVIDER_CNAMES["fastly.net"]="Fastly CDN"
    FINGERPRINTS["fastly.net"]="Fastly error: unknown domain"
    
    # Zendesk
    PROVIDER_CNAMES["zendesk.com"]="Zendesk"
    FINGERPRINTS["zendesk.com"]="Help Center Closed"
    
    # Unbounce
    PROVIDER_CNAMES["unbounce.com"]="Unbounce"
    FINGERPRINTS["unbounce.com"]="The requested URL was not found"
    
    # Statuspage
    PROVIDER_CNAMES["statuspage.io"]="Atlassian Statuspage"
    FINGERPRINTS["statuspage.io"]="You are being redirected|Status page"
    
    # Readme.io
    PROVIDER_CNAMES["readme.io"]="Readme.io"
    FINGERPRINTS["readme.io"]="Project doesnt exist"
    
    # Bitbucket
    PROVIDER_CNAMES["bitbucket.io"]="Bitbucket"
    FINGERPRINTS["bitbucket.io"]="Repository not found"
    
    # Cargo Collective
    PROVIDER_CNAMES["cargocollective.com"]="Cargo"
    FINGERPRINTS["cargocollective.com"]="404 Not Found"
    
    # Fly.io
    PROVIDER_CNAMES["fly.dev"]="Fly.io"
    FINGERPRINTS["fly.dev"]="404 Not Found"
    
    # Render
    PROVIDER_CNAMES["onrender.com"]="Render"
    FINGERPRINTS["onrender.com"]="Not Found"
    
    # Digital Ocean Spaces
    PROVIDER_CNAMES["digitaloceanspaces.com"]="DigitalOcean Spaces"
    FINGERPRINTS["digitaloceanspaces.com"]="NoSuchBucket"
    
    # Desk.com (Salesforce)
    PROVIDER_CNAMES["desk.com"]="Desk.com"
    FINGERPRINTS["desk.com"]="Please try again or try Desk.com free"
    
    # Tilda
    PROVIDER_CNAMES["tilda.ws"]="Tilda"
    FINGERPRINTS["tilda.ws"]="Please renew your subscription"
    
    # Wordpress.com
    PROVIDER_CNAMES["wordpress.com"]="WordPress.com"
    FINGERPRINTS["wordpress.com"]="Do you want to register"
    
    # HubSpot
    PROVIDER_CNAMES["hs-sites.com"]="HubSpot"
    FINGERPRINTS["hs-sites.com"]="Domain not found"
    
    # LaunchRock
    PROVIDER_CNAMES["launchrock.com"]="LaunchRock"
    FINGERPRINTS["launchrock.com"]="It looks like you may have taken a wrong turn"
    
    # Smugmug
    PROVIDER_CNAMES["smugmug.com"]="SmugMug"
    FINGERPRINTS["smugmug.com"]="Page Not Found"
    
    # Strikingly
    PROVIDER_CNAMES["s.strikinglydns.com"]="Strikingly"
    FINGERPRINTS["s.strikinglydns.com"]="page not found"
    
    # Uptimerobot
    PROVIDER_CNAMES["stats.uptimerobot.com"]="UptimeRobot"
    FINGERPRINTS["stats.uptimerobot.com"]="page not found"
    
    # Webflow
    PROVIDER_CNAMES["proxy.webflow.com"]="Webflow"
    FINGERPRINTS["proxy.webflow.com"]="The page you are looking for doesn't exist"
    
    PROVIDER_CNAMES["proxy-ssl.webflow.com"]="Webflow"
    FINGERPRINTS["proxy-ssl.webflow.com"]="The page you are looking for doesn't exist"
}

# ============================================================================
#                              DNS FUNCTIONS
# ============================================================================

# Resolve CNAME chain for a hostname
resolve_cname() {
    local host="$1"
    local resolvers="${2:-$DEFAULT_RESOLVERS}"
    local resolver
    
    # Pick first resolver
    resolver="${resolvers%%,*}"
    
    # Get CNAME chain (following all CNAMEs)
    dig +short +norecurse +tries=1 +time=3 CNAME "$host" "@$resolver" 2>/dev/null | \
        head -n1 | sed 's/\.$//'
}

# Get full CNAME chain
get_cname_chain() {
    local host="$1"
    local max_depth="${2:-10}"
    local resolvers="${3:-$DEFAULT_RESOLVERS}"
    local chain=()
    local current="$host"
    local depth=0
    
    while [[ $depth -lt $max_depth ]]; do
        local cname
        cname="$(resolve_cname "$current" "$resolvers" 2>/dev/null || true)"
        
        [[ -z "$cname" ]] && break
        
        chain+=("$cname")
        current="$cname"
        depth=$((depth + 1))
    done
    
    # Only print if chain has elements
    if [[ ${#chain[@]} -gt 0 ]]; then
        printf '%s\n' "${chain[@]}"
    fi
}

# Get final A record
resolve_a() {
    local host="$1"
    local resolvers="${2:-$DEFAULT_RESOLVERS}"
    local resolver="${resolvers%%,*}"
    
    dig +short +tries=1 +time=3 A "$host" "@$resolver" 2>/dev/null | head -n1
}

# Check if domain resolves to NXDOMAIN
is_nxdomain() {
    local host="$1"
    local resolvers="${2:-$DEFAULT_RESOLVERS}"
    local resolver="${resolvers%%,*}"
    
    local result
    result="$(dig +short +tries=1 +time=3 "$host" "@$resolver" 2>&1)"
    
    [[ -z "$result" ]] || [[ "$result" == *"NXDOMAIN"* ]] || [[ "$result" == *"SERVFAIL"* ]]
}

# ============================================================================
#                              HTTP FUNCTIONS
# ============================================================================

# Enhanced curl_fetch with better normalization
curl_fetch() {
    local url="$1"
    shift
    local extra_args=("$@")
    
    local tmpH tmpB res http_code url_eff server_hdr body_hash body_head
    
    tmpH="$(mktemp)"
    tmpB="$(mktemp)"
    local tmpW="${tmpH}.w"
    
    # Perform request with error handling
    # -L: follow redirects (max 3 to avoid loops)
    # -k: allow insecure SSL (common in takeover scenarios)
    curl -sS -k -L --max-redirs 3 \
        --connect-timeout "$TIMEOUT" \
        --max-time "$TIMEOUT" \
        -D "$tmpH" \
        -o "$tmpB" \
        -w "%{http_code}\t%{url_effective}" \
        "${extra_args[@]}" "$url" 2>>"${RUNLOG:-/dev/null}" > "$tmpW" || echo -e "000\tERROR" > "$tmpW"
    
    # Read output safely
    read -r http_code url_eff < "$tmpW" || { http_code="000"; url_eff="ERROR"; }
    
    # Extract server header (case insensitive)
    server_hdr="$(grep -i '^server:' "$tmpH" 2>/dev/null | head -n1 | cut -d':' -f2- | tr -d '\r' | xargs 2>/dev/null)" || server_hdr="_"
    
    # Normalize body content for hashing
    # Remove digits (timestamps, request IDs) to avoid false negatives
    local body_content
    body_content="$(head -c 4096 "$tmpB" 2>/dev/null)" || body_content=""
    body_head="$(echo "$body_content" | tr '\r\n' '  ' | tr -s ' ' | cut -c1-120)"
    
    # Hash normalized content (without digits)
    body_hash="$(echo "$body_content" | tr -d '0-9' | sha256sum | awk '{print $1}')"
    
    # Cleanup
    rm -f "$tmpH" "$tmpB" "$tmpW"
    
    # Return TSV format
    printf "%s\t%s\t%s\t%s\t%s\n" "$http_code" "$url_eff" "${server_hdr:-_}" "$body_hash" "${body_head:0:120}"
}

# ============================================================================
#                              PROVIDER DETECTION
# ============================================================================

# Identify cloud provider from CNAME
provider_from_cname() {
    local cname="$1"
    cname="${cname,,}"  # lowercase
    
    for pattern in "${!PROVIDER_CNAMES[@]}"; do
        if [[ "$cname" == *"$pattern"* ]]; then
            echo "${PROVIDER_CNAMES[$pattern]}"
            return 0
        fi
    done
    
    echo "Unknown"
}

# Get fingerprint pattern for CNAME
get_fingerprint() {
    local cname="$1"
    cname="${cname,,}"
    
    for pattern in "${!FINGERPRINTS[@]}"; do
        if [[ "$cname" == *"$pattern"* ]]; then
            echo "${FINGERPRINTS[$pattern]}"
            return 0
        fi
    done
    
    echo ""
}

# ============================================================================
#                              WILDCARD DETECTION
# ============================================================================

detect_wildcards() {
    local domain="$1"
    local resolvers="${2:-$DEFAULT_RESOLVERS}"
    
    log INFO "Detecting wildcard DNS for ${BOLD}$domain${RESET}"
    
    # Generate random subdomain
    local rnd
    rnd="$(openssl rand -hex 8)"
    local test_host="${rnd}.${domain}"
    
    local wildcard_ip wildcard_cname
    wildcard_ip="$(resolve_a "$test_host" "$resolvers")"
    wildcard_cname="$(resolve_cname "$test_host" "$resolvers")"
    
    if [[ -n "$wildcard_ip" ]]; then
        log WARN "Wildcard DNS detected! Random subdomain resolves to: $wildcard_ip"
        echo "$wildcard_ip"
        return 0
    fi
    
    if [[ -n "$wildcard_cname" ]]; then
        log WARN "Wildcard CNAME detected! Random subdomain points to: $wildcard_cname"
        echo "CNAME:$wildcard_cname"
        return 0
    fi
    
    log OK "No wildcard DNS detected"
    return 1
}

# ============================================================================
#                              SUBDOMAIN ENUMERATION
# ============================================================================

enumerate_subdomains() {
    local domain="$1"
    local output="$2"
    local methods="${3:-subfinder,amass}"
    
    log STEP "1/5: Subdomain Enumeration"
    
    local temp_subs
    temp_subs="$(mktemp)"
    
    # Subfinder
    if [[ "$methods" == *"subfinder"* ]] && command -v subfinder &>/dev/null; then
        log INFO "Running subfinder..."
        subfinder -d "$domain" -silent -t "$THREADS" 2>/dev/null >> "$temp_subs" || true
    fi
    
    # Amass (passive only for speed)
    if [[ "$methods" == *"amass"* ]] && command -v amass &>/dev/null; then
        log INFO "Running amass (passive)..."
        timeout 300 amass enum -passive -d "$domain" 2>/dev/null >> "$temp_subs" || true
    fi
    
    # Custom wordlist bruteforce (optional)
    if [[ -n "${WORDLIST:-}" ]] && [[ -f "$WORDLIST" ]]; then
        log INFO "Running wordlist bruteforce..."
        while IFS= read -r word; do
            echo "${word}.${domain}" >> "$temp_subs"
        done < "$WORDLIST"
    fi
    
    # Sort, dedupe, and filter
    sort -u "$temp_subs" | grep -E "^[a-zA-Z0-9]" > "$output"
    rm -f "$temp_subs"
    
    local count
    count="$(wc -l < "$output" | tr -d ' ')"
    log OK "Found ${BOLD}$count${RESET} unique subdomains"
}

# ============================================================================
#                              DNS RESOLUTION
# ============================================================================

resolve_all_dns() {
    local input="$1"
    local output="$2"
    local resolvers="${3:-$DEFAULT_RESOLVERS}"
    
    log STEP "2/5: DNS Resolution & CNAME Extraction"
    
    local total
    total="$(wc -l < "$input" | tr -d ' ')"
    
    > "$output"
    
    log INFO "Resolving DNS for ${BOLD}$total${RESET} subdomains..."
    
    # Process with progress indicator
    local count=0
    local found=0
    while IFS= read -r subdomain || [[ -n "$subdomain" ]]; do
        count=$((count + 1))
        
        # Show progress with current subdomain (unless silent)
        if [[ "${SILENT:-0}" != "1" ]]; then
            printf "\r${DIM}[%d/%d]${RESET} Resolving: ${CYAN}%-50s${RESET}" "$count" "$total" "${subdomain:0:50}"
        fi
        
        local cname_chain a_record
        cname_chain="$(get_cname_chain "$subdomain" 5 "$resolvers" | paste -sd ',' - 2>/dev/null || true)"
        a_record="$(resolve_a "$subdomain" "$resolvers" 2>/dev/null || true)"
        
        # Only include entries with CNAME (potential takeover targets)
        if [[ -n "$cname_chain" ]]; then
            local final_cname="${cname_chain##*,}"
            local provider
            provider="$(provider_from_cname "$final_cname")"
            
            printf "%s\t%s\t%s\t%s\n" "$subdomain" "$cname_chain" "${a_record:-NXDOMAIN}" "$provider" >> "$output"
            found=$((found + 1))
            
            # Verbose: show each CNAME found
            log VERBOSE "CNAME found: $subdomain -> $cname_chain ($provider)"
        fi
    done < "$input"
    
    # Clear line and show final status (unless silent)
    if [[ "${SILENT:-0}" != "1" ]]; then
        printf "\r%-80s\r" " "
        echo
    fi
    
    local count_with_cname
    count_with_cname="$(wc -l < "$output" | tr -d ' ')"
    log OK "Found ${BOLD}$count_with_cname${RESET} subdomains with CNAME records"
}

# ============================================================================
#                              INITIAL SCANNING (SUBZY/HTTPX)
# ============================================================================

run_automated_scan() {
    local input="$1"
    local output="$2"
    
    log STEP "3/5: Automated Vulnerability Scan"
    
    if command -v subzy &>/dev/null; then
        log INFO "Running subzy for initial detection..."
        
        # Create temp file with just hostnames
        local hosts_file
        hosts_file="$(mktemp)"
        cut -f1 "$input" > "$hosts_file"
        
        subzy run --targets "$hosts_file" --hide_fails --output "$output" 2>/dev/null || true
        
        rm -f "$hosts_file"
        
        if [[ -f "$output" ]] && [[ -s "$output" ]]; then
            local vuln_count
            vuln_count="$(grep -c "VULNERABLE" "$output" 2>/dev/null || echo 0)"
            log OK "Subzy found ${BOLD}$vuln_count${RESET} potential vulnerabilities"
        else
            log WARN "Subzy found no results"
            touch "$output"
        fi
    else
        log WARN "Subzy not installed, skipping automated scan"
        touch "$output"
    fi
}

# ============================================================================
#                              PROBABILITY SCORING
# ============================================================================

calculate_probability() {
    local subdomain="$1"
    local cname="$2"
    local http_code="$3"
    local body_content="$4"
    local provider="$5"
    local is_nxdomain="$6"
    
    local score=0
    local reasons=()
    
    # Factor 1: Known vulnerable provider
    if [[ "$provider" != "Unknown" ]]; then
        score=$((score + 30))
        reasons+=("Known provider: $provider")
    fi
    
    # Factor 2: NXDOMAIN on CNAME target
    if [[ "$is_nxdomain" == "true" ]]; then
        score=$((score + 35))
        reasons+=("CNAME target is NXDOMAIN")
    fi
    
    # Factor 3: HTTP response indicates takeover
    case "$http_code" in
        404)
            score=$((score + 15))
            reasons+=("HTTP 404 response")
            ;;
        502|503)
            score=$((score + 20))
            reasons+=("HTTP $http_code (backend error)")
            ;;
        000)
            score=$((score + 10))
            reasons+=("No HTTP response")
            ;;
    esac
    
    # Factor 4: Fingerprint match
    local fingerprint
    fingerprint="$(get_fingerprint "$cname" 2>/dev/null || true)"
    if [[ -n "$fingerprint" ]] && [[ "$body_content" =~ $fingerprint ]]; then
        score=$((score + 40))
        reasons+=("Fingerprint matched: $fingerprint")
    fi
    
    # Cap at 100
    [[ $score -gt 100 ]] && score=100
    
    # Return score and reasons
    local reasons_str=""
    [[ ${#reasons[@]} -gt 0 ]] && reasons_str="$(IFS=';'; echo "${reasons[*]}")"
    printf "%d\t%s\n" "$score" "$reasons_str"
}

# ============================================================================
#                              DEEP VERIFICATION
# ============================================================================

verify_candidate() {
    local subdomain="$1"
    local cname="$2"
    local provider="$3"
    
    local result_code result_body result_line
    local is_nxdomain="false"
    local final_cname="${cname##*,}"
    
    # Check if CNAME target is NXDOMAIN
    if is_nxdomain "$final_cname"; then
        is_nxdomain="true"
    fi
    
    # Fetch the subdomain
    result_line="$(curl_fetch "https://$subdomain")"
    IFS=$'\t' read -r http_code url_eff server body_hash body_preview <<< "$result_line"
    
    # If HTTPS failed, try HTTP
    if [[ "$http_code" == "000" ]]; then
        result_line="$(curl_fetch "http://$subdomain")"
        IFS=$'\t' read -r http_code url_eff server body_hash body_preview <<< "$result_line"
    fi
    
    # Calculate probability score
    local score_data
    score_data="$(calculate_probability "$subdomain" "$final_cname" "$http_code" "$body_preview" "$provider" "$is_nxdomain")"
    IFS=$'\t' read -r score reasons <<< "$score_data"
    
    # Determine status
    local status
    if [[ $score -ge 70 ]]; then
        status="VULNERABLE"
    elif [[ $score -ge 40 ]]; then
        status="HIGH"
    elif [[ $score -ge 20 ]]; then
        status="MEDIUM"
    else
        status="LOW"
    fi
    
    # Output result
    printf "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n" \
        "$subdomain" "$cname" "$provider" "$http_code" "$is_nxdomain" \
        "$score" "$status" "$reasons"
}

# Export function for parallel execution
export -f verify_candidate curl_fetch calculate_probability get_fingerprint is_nxdomain
export TIMEOUT DEFAULT_RESOLVERS

run_deep_verification() {
    local input="$1"
    local output="$2"
    
    log STEP "4/5: Deep Verification"
    
    local total
    total="$(wc -l < "$input" | tr -d ' ')"
    
    if [[ $total -eq 0 ]]; then
        log WARN "No candidates to verify"
        touch "$output"
        return
    fi
    
    log INFO "Verifying ${BOLD}$total${RESET} candidates..."
    
    # Header
    echo -e "subdomain\tcname\tprovider\thttp_code\tnxdomain\tscore\tstatus\treasons" > "$output"
    
    if command -v parallel &>/dev/null && [[ $total -gt 5 ]]; then
        log INFO "Using GNU Parallel for faster verification"
        
        while IFS=$'\t' read -r subdomain cname_chain a_record provider; do
            echo "$subdomain	$cname_chain	$provider"
        done < "$input" | \
        parallel -j "$THREADS" --colsep '\t' \
            "verify_candidate {1} {2} {3}" >> "$output" 2>/dev/null
    else
        # Sequential fallback
        local count=0
        while IFS=$'\t' read -r subdomain cname_chain a_record provider; do
            count=$((count + 1))
            progress_bar "$count" "$total"
            verify_candidate "$subdomain" "$cname_chain" "$provider" >> "$output"
        done < "$input"
        echo  # Newline after progress
    fi
    
    local vuln_count high_count
    vuln_count="$(grep -c "VULNERABLE" "$output" 2>/dev/null || echo 0)"
    high_count="$(grep -c "HIGH" "$output" 2>/dev/null || echo 0)"
    
    log OK "Verification complete: ${RED}$vuln_count vulnerable${RESET}, ${YELLOW}$high_count high probability${RESET}"
}

# ============================================================================
#                              REPORTING
# ============================================================================

generate_reports() {
    local results_file="$1"
    local output_dir="$2"
    
    log STEP "5/5: Generating Reports"
    
    # JSON Report
    local json_file="${output_dir}/results.json"
    log INFO "Generating JSON report..."
    
    {
        echo "{"
        echo "  \"scan_info\": {"
        echo "    \"domain\": \"$DOMAIN\","
        echo "    \"timestamp\": \"$(date -Iseconds)\","
        echo "    \"version\": \"$VERSION\""
        echo "  },"
        echo "  \"results\": ["
        
        local first=true
        tail -n +2 "$results_file" | while IFS=$'\t' read -r subdomain cname provider http_code nxdomain score status reasons; do
            [[ "$first" == "true" ]] && first=false || echo ","
            printf '    {"subdomain": "%s", "cname": "%s", "provider": "%s", "http_code": "%s", "nxdomain": %s, "score": %d, "status": "%s", "reasons": "%s"}' \
                "$subdomain" "$cname" "$provider" "$http_code" "$nxdomain" "$score" "$status" "$reasons"
        done
        
        echo ""
        echo "  ]"
        echo "}"
    } > "$json_file"
    
    # HTML Report
    local html_file="${output_dir}/report.html"
    log INFO "Generating HTML report..."
    
    cat > "$html_file" << 'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubTake Flow - Scan Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Grotesk:wght@400;700&display=swap');
        
        :root {
            --bg-dark: #0a0e17;
            --bg-card: #111827;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
            --accent-green: #10b981;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --border: #1f2937;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Space Grotesk', sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
            background-image: 
                radial-gradient(ellipse at top, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
                radial-gradient(ellipse at bottom right, rgba(139, 92, 246, 0.1) 0%, transparent 50%);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .header {
            text-align: center;
            margin-bottom: 3rem;
            padding: 2rem;
            background: linear-gradient(135deg, var(--bg-card) 0%, rgba(59, 130, 246, 0.1) 100%);
            border-radius: 1rem;
            border: 1px solid var(--border);
        }
        
        .logo {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.5rem;
            color: var(--accent-blue);
            margin-bottom: 1rem;
            white-space: pre;
            line-height: 1.2;
        }
        
        h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .meta {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.5rem;
            text-align: center;
            transition: transform 0.2s, border-color 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            border-color: var(--accent-blue);
        }
        
        .stat-card.critical { border-left: 4px solid var(--accent-red); }
        .stat-card.high { border-left: 4px solid var(--accent-yellow); }
        .stat-card.medium { border-left: 4px solid var(--accent-blue); }
        .stat-card.low { border-left: 4px solid var(--accent-green); }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }
        
        .stat-card.critical .stat-value { color: var(--accent-red); }
        .stat-card.high .stat-value { color: var(--accent-yellow); }
        .stat-card.medium .stat-value { color: var(--accent-blue); }
        .stat-card.low .stat-value { color: var(--accent-green); }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .results-table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 0.75rem;
            overflow: hidden;
            border: 1px solid var(--border);
        }
        
        .results-table th {
            background: rgba(59, 130, 246, 0.1);
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            color: var(--accent-blue);
            border-bottom: 2px solid var(--border);
            cursor: pointer;
            user-select: none;
        }
        
        .results-table th:hover {
            background: rgba(59, 130, 246, 0.2);
        }
        
        .results-table td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }
        
        .results-table tr:hover {
            background: rgba(59, 130, 246, 0.05);
        }
        
        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status-VULNERABLE { background: var(--accent-red); color: white; }
        .status-HIGH { background: var(--accent-yellow); color: black; }
        .status-MEDIUM { background: var(--accent-blue); color: white; }
        .status-LOW { background: var(--bg-dark); color: var(--text-secondary); border: 1px solid var(--border); }
        
        .score-bar {
            width: 100px;
            height: 8px;
            background: var(--bg-dark);
            border-radius: 4px;
            overflow: hidden;
        }
        
        .score-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        
        .score-fill.high { background: linear-gradient(90deg, var(--accent-red), var(--accent-yellow)); }
        .score-fill.medium { background: linear-gradient(90deg, var(--accent-yellow), var(--accent-blue)); }
        .score-fill.low { background: var(--accent-green); }
        
        .footer {
            text-align: center;
            margin-top: 2rem;
            padding: 1rem;
            color: var(--text-secondary);
            font-size: 0.8rem;
        }
        
        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .results-table { display: block; overflow-x: auto; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo">
 ___       _   _____     _
/ __> _ _ | |_|_   _|___| |_ ___
\__ \| | || . | | | <_> | / / ._>
<___/`___||___| |_| <___|_\_\___.</div>
            <h1>Subdomain Takeover Report</h1>
HTMLHEAD

    # Add scan metadata
    echo "            <p class=\"meta\">Domain: <strong>$DOMAIN</strong> | Scanned: $(date '+%Y-%m-%d %H:%M:%S') | Version: $VERSION</p>" >> "$html_file"
    echo "        </header>" >> "$html_file"
    
    # Calculate stats
    local total vuln_count high_count medium_count low_count
    total=$(($(wc -l < "$results_file") - 1))
    vuln_count=$(grep -c "VULNERABLE" "$results_file" 2>/dev/null || echo 0)
    high_count=$(grep -c $'\tHIGH\t' "$results_file" 2>/dev/null || echo 0)
    medium_count=$(grep -c $'\tMEDIUM\t' "$results_file" 2>/dev/null || echo 0)
    low_count=$(grep -c $'\tLOW\t' "$results_file" 2>/dev/null || echo 0)
    
    # Stats cards
    cat >> "$html_file" << HTMLSTATS
        <div class="stats">
            <div class="stat-card critical">
                <div class="stat-value">$vuln_count</div>
                <div class="stat-label">Vulnerable</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">$high_count</div>
                <div class="stat-label">High Probability</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">$medium_count</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">$low_count</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <table class="results-table">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Subdomain</th>
                    <th onclick="sortTable(1)">CNAME</th>
                    <th onclick="sortTable(2)">Provider</th>
                    <th onclick="sortTable(3)">HTTP</th>
                    <th onclick="sortTable(4)">Score</th>
                    <th onclick="sortTable(5)">Status</th>
                </tr>
            </thead>
            <tbody>
HTMLSTATS

    # Add table rows
    tail -n +2 "$results_file" | sort -t$'\t' -k6 -nr | while IFS=$'\t' read -r subdomain cname provider http_code nxdomain score status reasons; do
        local score_class="low"
        [[ $score -ge 40 ]] && score_class="medium"
        [[ $score -ge 70 ]] && score_class="high"
        
        cat >> "$html_file" << HTMLROW
                <tr>
                    <td>$subdomain</td>
                    <td title="$cname">${cname:0:50}...</td>
                    <td>$provider</td>
                    <td>$http_code</td>
                    <td>
                        <div class="score-bar">
                            <div class="score-fill $score_class" style="width: ${score}%"></div>
                        </div>
                        <small>$score%</small>
                    </td>
                    <td><span class="status-badge status-$status">$status</span></td>
                </tr>
HTMLROW
    done

    # Close HTML
    cat >> "$html_file" << 'HTMLFOOT'
            </tbody>
        </table>
        
        <footer class="footer">
            <p>Generated by SubTake Flow v2.0.0 | https://github.com/W4RRR/subtake</p>
        </footer>
    </div>
    
    <script>
        function sortTable(n) {
            const table = document.querySelector('.results-table');
            const rows = Array.from(table.querySelectorAll('tbody tr'));
            const isNumeric = n === 3 || n === 4;
            
            rows.sort((a, b) => {
                const aVal = a.cells[n].textContent.trim();
                const bVal = b.cells[n].textContent.trim();
                
                if (isNumeric) {
                    return parseFloat(bVal) - parseFloat(aVal);
                }
                return aVal.localeCompare(bVal);
            });
            
            const tbody = table.querySelector('tbody');
            rows.forEach(row => tbody.appendChild(row));
        }
    </script>
</body>
</html>
HTMLFOOT

    log OK "Reports generated:"
    echo -e "    ${SYMBOL_ARROW} ${CYAN}${json_file}${RESET}"
    echo -e "    ${SYMBOL_ARROW} ${CYAN}${html_file}${RESET}"
}

# ============================================================================
#                              SUMMARY
# ============================================================================

print_summary() {
    local results_file="$1"
    
    # Vulnerable findings
    local vuln_results
    vuln_results="$(grep "VULNERABLE" "$results_file" 2>/dev/null || true)"
    
    # High probability findings
    local high_results
    high_results="$(grep $'\tHIGH\t' "$results_file" 2>/dev/null || true)"
    
    # Silent mode: minimal output
    if [[ "${SILENT:-0}" == "1" ]]; then
        if [[ -n "$vuln_results" ]]; then
            echo -e "\n${BG_RED}${WHITE}${BOLD} VULNERABLE ${RESET}"
            while IFS=$'\t' read -r subdomain cname provider http_code nxdomain score status reasons; do
                echo -e "  ${RED}☠${RESET} $subdomain -> $cname ($provider)"
            done <<< "$vuln_results"
        fi
        if [[ -n "$high_results" ]]; then
            echo -e "\n${YELLOW}${BOLD}HIGH PROBABILITY:${RESET}"
            while IFS=$'\t' read -r subdomain cname provider http_code nxdomain score status reasons; do
                echo -e "  ${YELLOW}●${RESET} $subdomain"
            done <<< "$high_results"
        fi
        [[ -z "$vuln_results" ]] && [[ -z "$high_results" ]] && echo -e "${GREEN}No vulnerabilities found${RESET}"
        return
    fi
    
    # Normal/Verbose mode
    echo
    echo -e "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${WHITE}                        SCAN SUMMARY                           ${RESET}"
    echo -e "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════${RESET}"
    echo
    
    if [[ -n "$vuln_results" ]]; then
        echo -e "${BG_RED}${WHITE}${BOLD} ☠  VULNERABLE SUBDOMAINS FOUND ${RESET}"
        echo
        while IFS=$'\t' read -r subdomain cname provider http_code nxdomain score status reasons; do
            echo -e "  ${RED}●${RESET} ${BOLD}$subdomain${RESET}"
            echo -e "    ${DIM}CNAME:${RESET} $cname"
            echo -e "    ${DIM}Provider:${RESET} $provider"
            echo -e "    ${DIM}Score:${RESET} ${score}%"
            # Verbose: show reasons
            [[ "${VERBOSE:-0}" == "1" ]] && [[ -n "$reasons" ]] && echo -e "    ${DIM}Reasons:${RESET} $reasons"
            echo
        done <<< "$vuln_results"
    else
        echo -e "${GREEN}${BOLD}✓ No confirmed vulnerabilities found${RESET}"
    fi
    
    if [[ -n "$high_results" ]]; then
        echo
        echo -e "${BG_YELLOW}${WHITE}${BOLD} 🔥 HIGH PROBABILITY (Manual Review Recommended) ${RESET}"
        echo
        while IFS=$'\t' read -r subdomain cname provider http_code nxdomain score status reasons; do
            echo -e "  ${YELLOW}●${RESET} $subdomain ${DIM}($provider, ${score}%)${RESET}"
            # Verbose: show more details
            [[ "${VERBOSE:-0}" == "1" ]] && echo -e "    ${DIM}CNAME: $cname${RESET}"
        done <<< "$high_results"
    fi
    
    # Verbose: show medium findings too
    if [[ "${VERBOSE:-0}" == "1" ]]; then
        local medium_results
        medium_results="$(grep $'\tMEDIUM\t' "$results_file" 2>/dev/null || true)"
        if [[ -n "$medium_results" ]]; then
            echo
            echo -e "${BLUE}${BOLD}MEDIUM PROBABILITY:${RESET}"
            while IFS=$'\t' read -r subdomain cname provider http_code nxdomain score status reasons; do
                echo -e "  ${BLUE}●${RESET} $subdomain ${DIM}($provider, ${score}%)${RESET}"
            done <<< "$medium_results"
        fi
    fi
    
    echo
    echo -e "${DIM}Full results saved to: ${OUTDIR}${RESET}"
    echo
}

# ============================================================================
#                              HELP & USAGE
# ============================================================================

show_help() {
    show_banner
    
    echo -e "${BOLD}USAGE:${RESET}"
    echo "    $0 [OPTIONS] <domain>"
    echo
    echo -e "${BOLD}DESCRIPTION:${RESET}"
    echo "    SubTake Flow is an advanced subdomain takeover detection tool with"
    echo "    intelligent heuristics designed to minimize false positives while"
    echo "    maximizing detection of vulnerable subdomains."
    echo
    echo -e "${BOLD}OPTIONS:${RESET}"
    echo -e "    ${CYAN}-o, --output${RESET} <dir>       Output directory (default: ./subtake_<domain>)"
    echo -e "    ${CYAN}-t, --timeout${RESET} <sec>      HTTP timeout in seconds (default: ${DEFAULT_TIMEOUT})"
    echo -e "    ${CYAN}-j, --threads${RESET} <num>      Number of parallel threads (default: ${DEFAULT_THREADS})"
    echo -e "    ${CYAN}-r, --resolvers${RESET} <list>   Comma-separated DNS resolvers (default: ${DEFAULT_RESOLVERS})"
    echo -e "    ${CYAN}-w, --wordlist${RESET} <file>    Custom wordlist for subdomain bruteforce"
    echo -e "    ${CYAN}-s, --subdomains${RESET} <file>  Use existing subdomain list instead of enumeration"
    echo -e "    ${CYAN}-f, --fingerprints${RESET} <f>   Custom fingerprints YAML file"
    echo -e "    ${CYAN}--skip-enum${RESET}              Skip subdomain enumeration (requires -s)"
    echo -e "    ${CYAN}--skip-subzy${RESET}             Skip subzy automated scan"
    echo -e "    ${CYAN}-v, --verbose${RESET}            Enable verbose output (show more details)"
    echo -e "    ${CYAN}-q, --quiet, --silent${RESET}    Silent mode (only show vulnerabilities and errors)"
    echo -e "    ${CYAN}--debug${RESET}                  Enable debug output"
    echo -e "    ${CYAN}-h, --help${RESET}               Show this help message"
    echo -e "    ${CYAN}--version${RESET}                Show version"
    echo
    echo -e "${BOLD}EXAMPLES:${RESET}"
    echo -e "    ${DIM}# Basic scan${RESET}"
    echo "    $0 example.com"
    echo
    echo -e "    ${DIM}# Custom output and threads${RESET}"
    echo "    $0 -o /tmp/results -j 20 example.com"
    echo
    echo -e "    ${DIM}# Use existing subdomain list${RESET}"
    echo "    $0 -s subdomains.txt --skip-enum example.com"
    echo
    echo -e "    ${DIM}# With custom wordlist${RESET}"
    echo "    $0 -w wordlist.txt example.com"
    echo
    echo -e "${BOLD}OUTPUT:${RESET}"
    echo "    The tool generates the following files:"
    echo -e "    - ${CYAN}subdomains.txt${RESET}    Raw subdomain list"
    echo -e "    - ${CYAN}dns_resolved.tsv${RESET}  DNS resolution with CNAMEs"
    echo -e "    - ${CYAN}results.tsv${RESET}       Final verification results"
    echo -e "    - ${CYAN}results.json${RESET}      JSON format results"
    echo -e "    - ${CYAN}report.html${RESET}       Interactive HTML report"
    echo -e "    - ${CYAN}scan.log${RESET}          Detailed scan log"
    echo
    echo -e "${BOLD}MORE INFO:${RESET}"
    echo "    https://github.com/W4RRR/subtake"
    echo
}

# ============================================================================
#                              ARGUMENT PARSING
# ============================================================================

parse_args() {
    TIMEOUT="${DEFAULT_TIMEOUT}"
    THREADS="${DEFAULT_THREADS}"
    RESOLVERS="${DEFAULT_RESOLVERS}"
    OUTDIR=""
    WORDLIST=""
    SUBDOMAIN_FILE=""
    SKIP_ENUM=false
    SKIP_SUBZY=false
    DEBUG=0
    VERBOSE=0
    SILENT=0
    DOMAIN=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)
                OUTDIR="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -j|--threads)
                THREADS="$2"
                shift 2
                ;;
            -r|--resolvers)
                RESOLVERS="$2"
                shift 2
                ;;
            -w|--wordlist)
                WORDLIST="$2"
                shift 2
                ;;
            -s|--subdomains)
                SUBDOMAIN_FILE="$2"
                shift 2
                ;;
            -f|--fingerprints)
                FINGERPRINTS_FILE="$2"
                shift 2
                ;;
            --skip-enum)
                SKIP_ENUM=true
                shift
                ;;
            --skip-subzy)
                SKIP_SUBZY=true
                shift
                ;;
            --debug)
                DEBUG=1
                shift
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -q|--quiet|--silent)
                SILENT=1
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            --version)
                echo "SubTake Flow v${VERSION}"
                exit 0
                ;;
            -*)
                log ERROR "Unknown option: $1"
                echo "Use -h for help"
                exit 1
                ;;
            *)
                DOMAIN="$1"
                shift
                ;;
        esac
    done
    
    # Validate domain
    if [[ -z "$DOMAIN" ]]; then
        log ERROR "Domain is required"
        echo "Use -h for help"
        exit 1
    fi
    
    # Set default output directory
    [[ -z "$OUTDIR" ]] && OUTDIR="./subtake_${DOMAIN}"
    
    # Validate skip-enum requires subdomain file
    if [[ "$SKIP_ENUM" == "true" ]] && [[ -z "$SUBDOMAIN_FILE" ]]; then
        log ERROR "--skip-enum requires -s/--subdomains"
        exit 1
    fi
    
    # Verbose and silent are mutually exclusive
    if [[ "$VERBOSE" == "1" ]] && [[ "$SILENT" == "1" ]]; then
        log WARN "Cannot use --verbose and --silent together. Using normal mode."
        VERBOSE=0
        SILENT=0
    fi
    
    # Export for subshells
    export TIMEOUT THREADS RESOLVERS DEBUG VERBOSE SILENT
}

# ============================================================================
#                              MAIN EXECUTION
# ============================================================================

main() {
    parse_args "$@"
    
    show_banner
    
    # Setup output directory
    mkdir -p "$OUTDIR"
    RUNLOG="${OUTDIR}/scan.log"
    
    # Define output files
    SUBDOMAINS="${OUTDIR}/subdomains.txt"
    DNS_RESOLVED="${OUTDIR}/dns_resolved.tsv"
    SUBZY_OUT="${OUTDIR}/subzy_results.txt"
    VERIFY="${OUTDIR}/results.tsv"
    
    log INFO "Target domain: ${BOLD}$DOMAIN${RESET}"
    log INFO "Output directory: ${BOLD}$OUTDIR${RESET}"
    echo
    
    # Check dependencies
    check_all_dependencies
    echo
    
    # Load fingerprints
    load_fingerprints
    echo
    
    # Step 0: Wildcard detection
    log STEP "0/5: Wildcard Detection"
    WILDCARD=""
    if WILDCARD="$(detect_wildcards "$DOMAIN" "$RESOLVERS")"; then
        log WARN "Wildcard detected: $WILDCARD"
        log WARN "Results may contain false positives"
    fi
    echo
    
    # Step 1: Subdomain enumeration
    if [[ "$SKIP_ENUM" == "true" ]]; then
        log INFO "Skipping enumeration, using provided file: $SUBDOMAIN_FILE"
        cp "$SUBDOMAIN_FILE" "$SUBDOMAINS"
    else
        enumerate_subdomains "$DOMAIN" "$SUBDOMAINS"
    fi
    echo
    
    # Step 2: DNS resolution
    resolve_all_dns "$SUBDOMAINS" "$DNS_RESOLVED" "$RESOLVERS"
    echo
    
    # Step 3: Automated scan
    if [[ "$SKIP_SUBZY" != "true" ]]; then
        run_automated_scan "$DNS_RESOLVED" "$SUBZY_OUT"
    else
        log INFO "Skipping subzy scan"
        touch "$SUBZY_OUT"
    fi
    echo
    
    # Step 4: Deep verification
    run_deep_verification "$DNS_RESOLVED" "$VERIFY"
    echo
    
    # Step 5: Generate reports
    generate_reports "$VERIFY" "$OUTDIR"
    echo
    
    # Print summary
    print_summary "$VERIFY"
    
    log OK "Scan complete! Total time: ${SECONDS}s"
}

# Run main function
main "$@"

