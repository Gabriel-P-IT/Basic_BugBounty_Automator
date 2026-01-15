# =====================================================================
# Prérequis
# - Go installé et à jour.
# - IMPORTANT: les binaires Go installés via "go install" vont dans:
#   $(go env GOPATH)/bin (souvent $HOME/go/bin)
# =====================================================================

# Mettre les binaires Go en priorité dans le PATH (évite "command not found"
# et évite le conflit avec /usr/bin/httpx)
echo 'export PATH="$HOME/.local/go/bin:$(go env GOPATH)/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
hash -r


# =====================================================================
# GF (tomnomnom)
# =====================================================================
go install github.com/tomnomnom/gf@latest
hash -r

# Vérifier
command -v gf
gf -h


# =====================================================================
# Subfinder (ProjectDiscovery)
# =====================================================================
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
hash -r

# Vérifier
command -v subfinder
subfinder -h


# =====================================================================
# httpx (ProjectDiscovery)
# =====================================================================
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
hash -r

# Vérifier (doit afficher les options ProjectDiscovery comme -silent, -mc, -rate-limit)
command -v httpx
httpx -h | head -20


# =====================================================================
# Katana (ProjectDiscovery)
# =====================================================================
go install github.com/projectdiscovery/katana/cmd/katana@latest
hash -r

# Vérifier
command -v katana
katana -h


# =====================================================================
# Nuclei (ProjectDiscovery)
# =====================================================================
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
hash -r

# Templates (optionnel mais recommandé)
nuclei -ut -ud "$HOME/nuclei-templates"

# Vérifier
command -v nuclei
nuclei -h | head -20


# =====================================================================
# Subzy (PentestPad)
# =====================================================================
go install -v github.com/PentestPad/subzy@latest
hash -r

# Vérifier
command -v subzy
subzy -h


# =====================================================================
# ffuf
# =====================================================================
go install github.com/ffuf/ffuf/v2@latest
hash -r

# Vérifier
command -v ffuf
ffuf -h


# =====================================================================
# feroxbuster (Kali - recommandé via apt)
# =====================================================================
sudo apt update && sudo apt install -y feroxbuster

# Vérifier
command -v feroxbuster
feroxbuster -V


# =====================================================================
# Vérification globale
# =====================================================================
command -v subfinder httpx katana nuclei subzy ffuf feroxbuster gf
