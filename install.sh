#!/usr/bin/env bash
#
# SubTake Flow - Installation Script
# Installs dependencies and sets up the tool
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

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

EOF
echo -e "${RESET}"
echo -e "${BOLD}Installation Script${RESET}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt &>/dev/null; then
            echo "debian"
        elif command -v yum &>/dev/null; then
            echo "rhel"
        elif command -v pacman &>/dev/null; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)
echo -e "${BLUE}ℹ${RESET} Detected OS: ${BOLD}$OS${RESET}"
echo

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}⚠${RESET} Running as root. This is not recommended."
    echo -e "  Consider running as a regular user with sudo privileges."
    echo
fi

# Install required dependencies
install_required() {
    echo -e "${BOLD}Installing required dependencies...${RESET}"
    echo
    
    case "$OS" in
        debian)
            echo -e "${BLUE}→${RESET} Running apt update..."
            sudo apt update -qq
            
            echo -e "${BLUE}→${RESET} Installing: dnsutils curl jq openssl"
            sudo apt install -y dnsutils curl jq openssl
            ;;
        rhel)
            echo -e "${BLUE}→${RESET} Installing: bind-utils curl jq openssl"
            sudo yum install -y bind-utils curl jq openssl
            ;;
        arch)
            echo -e "${BLUE}→${RESET} Installing: bind curl jq openssl"
            sudo pacman -S --noconfirm bind curl jq openssl
            ;;
        macos)
            if ! command -v brew &>/dev/null; then
                echo -e "${RED}✗${RESET} Homebrew not found. Please install it first:"
                echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
                exit 1
            fi
            
            echo -e "${BLUE}→${RESET} Installing: bind curl jq openssl"
            brew install bind curl jq openssl
            ;;
        *)
            echo -e "${YELLOW}⚠${RESET} Unknown OS. Please install manually:"
            echo "  - dig (dnsutils/bind-utils)"
            echo "  - curl"
            echo "  - jq"
            echo "  - openssl"
            ;;
    esac
    
    echo
    echo -e "${GREEN}✓${RESET} Required dependencies installed"
}

# Install optional Go tools
install_go_tools() {
    echo
    echo -e "${BOLD}Installing optional Go tools...${RESET}"
    echo -e "${YELLOW}⚠${RESET} This requires Go to be installed"
    echo
    
    if ! command -v go &>/dev/null; then
        echo -e "${YELLOW}⚠${RESET} Go not found. Skipping Go tool installation."
        echo "  Install Go from: https://golang.org/dl/"
        return
    fi
    
    # Ensure GOPATH/bin is in PATH
    export PATH="$PATH:$(go env GOPATH)/bin"
    
    echo -e "${BLUE}→${RESET} Installing subfinder..."
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || echo -e "${YELLOW}⚠${RESET} Failed to install subfinder"
    
    echo -e "${BLUE}→${RESET} Installing httpx..."
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || echo -e "${YELLOW}⚠${RESET} Failed to install httpx"
    
    echo -e "${BLUE}→${RESET} Installing subzy..."
    go install github.com/PentestPad/subzy@latest 2>/dev/null || echo -e "${YELLOW}⚠${RESET} Failed to install subzy"
    
    echo
    echo -e "${GREEN}✓${RESET} Go tools installation attempted"
    echo -e "  Add to PATH: export PATH=\"\$PATH:\$(go env GOPATH)/bin\""
}

# Install GNU Parallel
install_parallel() {
    echo
    echo -e "${BOLD}Installing GNU Parallel...${RESET}"
    
    case "$OS" in
        debian)
            sudo apt install -y parallel
            ;;
        rhel)
            sudo yum install -y parallel
            ;;
        arch)
            sudo pacman -S --noconfirm parallel
            ;;
        macos)
            brew install parallel
            ;;
        *)
            echo -e "${YELLOW}⚠${RESET} Please install GNU Parallel manually"
            ;;
    esac
    
    # Silence the citation notice
    mkdir -p ~/.parallel
    touch ~/.parallel/will-cite 2>/dev/null || true
    
    echo -e "${GREEN}✓${RESET} GNU Parallel installed"
}

# Setup the tool
setup_tool() {
    echo
    echo -e "${BOLD}Setting up SubTake Flow...${RESET}"
    
    # Make executable
    chmod +x subtake.sh
    echo -e "${GREEN}✓${RESET} Made subtake.sh executable"
    
    # Create symlink (optional)
    echo
    read -p "Create symlink in /usr/local/bin? [y/N] " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo ln -sf "$(pwd)/subtake.sh" /usr/local/bin/subtake
        echo -e "${GREEN}✓${RESET} Symlink created: subtake → $(pwd)/subtake.sh"
        echo -e "  You can now run: ${CYAN}subtake example.com${RESET}"
    fi
}

# Verify installation
verify_installation() {
    echo
    echo -e "${BOLD}Verifying installation...${RESET}"
    echo
    
    local required=(dig curl jq openssl)
    local optional=(subfinder httpx subzy parallel)
    local missing_required=0
    local missing_optional=0
    
    echo "Required:"
    for tool in "${required[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}✓${RESET} $tool"
        else
            echo -e "  ${RED}✗${RESET} $tool"
            ((missing_required++))
        fi
    done
    
    echo
    echo "Optional:"
    for tool in "${optional[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}✓${RESET} $tool"
        else
            echo -e "  ${YELLOW}○${RESET} $tool (not installed)"
            ((missing_optional++))
        fi
    done
    
    echo
    
    if [[ $missing_required -gt 0 ]]; then
        echo -e "${RED}✗${RESET} Installation incomplete. Missing $missing_required required tool(s)."
        return 1
    fi
    
    echo -e "${GREEN}✓${RESET} Installation complete!"
    
    if [[ $missing_optional -gt 0 ]]; then
        echo -e "${YELLOW}⚠${RESET} $missing_optional optional tool(s) not installed. Some features will be limited."
    fi
}

# Main menu
main() {
    echo "Select installation type:"
    echo
    echo "  1) Full install (required + optional tools)"
    echo "  2) Minimal install (required only)"
    echo "  3) Verify installation"
    echo "  4) Exit"
    echo
    read -p "Choice [1-4]: " choice
    
    case "$choice" in
        1)
            install_required
            install_parallel
            install_go_tools
            setup_tool
            verify_installation
            ;;
        2)
            install_required
            setup_tool
            verify_installation
            ;;
        3)
            verify_installation
            ;;
        4)
            echo "Bye!"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${RESET}"
            exit 1
            ;;
    esac
    
    echo
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${GREEN}  SubTake Flow is ready to use!${RESET}"
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo
    echo -e "Quick start:"
    echo -e "  ${CYAN}./subtake.sh --help${RESET}      Show help"
    echo -e "  ${CYAN}./subtake.sh example.com${RESET} Run a scan"
    echo
}

main

