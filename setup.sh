#!/usr/bin/zsh

# Colors setup
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
initial_dir=$(pwd)

#Check if script is ran as root
if [ "$EUID" -ne 0 ]
  then echo "${RED}Please run as root!${NC}"
  exit
fi

# Check OS
OS=$(lsb_release -a 2>/dev/null | grep 'Distributor ID' | awk '{print $3}')
if [ "$(echo $HOSTNAME | awk -F '-' '{print $1}')" = "exegol" ]; then
    OS="Exegol"
    source /opt/.exegol_aliases
fi

# Echo information
if [ "$OS" = "Kali" ]; then
    echo "\n${GREEN}Kali Linux detected. The script can proceed with installation${NC}\n"
elif [ "$OS" = "Exegol" ] || [ "$OS" = "Ubuntu" ] || [ "$OS" = "Debian" ]; then
    echo "\n${GREEN}$OS detected. The script can proceed with installation${NC}\n"
else
    echo "\n${RED}This script has to be ran in Kali Linux, Exegol, Debian or Ubuntu! Other systems are not yet supported${NC}\n"
    exit 1
fi

# Update repositories
apt-get update

# Install required packages via apt

## Install jq
command -v "jq" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        apt-get install jq -y
    fi

## Install git
command -v "git" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        apt-get install git -y
    fi

## Install go
command -v "go" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ] || [ "$OS" = "Debian" ] || [ "$OS" = "Exegol" ]; then
            apt-get install gccgo-go -y
            if [ "$OS" = "Kali" ]; then
                export PATH=$PATH:/root/go/bin
            fi
        elif [ "$OS" = "Ubuntu" ]; then
            wget https://dl.google.com/go/go1.21.3.linux-amd64.tar.gz
            tar -xvf go1.21.3.linux-amd64.tar.gz
            mv go /usr/local
            export GOROOT=/usr/local/go
            export GOPATH=$HOME/go
            export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
            rm -rf go1.21.3.linux-amd64.tar.gz
        fi
    fi

## Install whois
command -v "whois" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        apt-get install whois -y
    fi

## Install curl
command -v "curl" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        apt-get install curl -y
    fi

## Install wget
command -v "wget" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        apt-get install wget -y
    fi

## Install pip2
command -v "pip2" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Ubuntu" ]; then
            apt-get install python2 -y
            wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
            python2 get-pip.py
            rm -rf get-pip.py
        else
            wget https://gist.githubusercontent.com/anir0y/a20246e26dcb2ebf1b44a0e1d989f5d1/raw/a9908e5dd147f0b6eb71ec51f9845fafe7fb8a7f/pip2%2520install -O run.sh 
            chmod +x run.sh
            ./run.sh
            rm -rf run.sh
        fi
    fi

## Install nuclei
command -v "nuclei" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ]; then
            apt-get install nuclei -y
        elif [ "$OS" = "Ubuntu" ] || [ "$OS" = "Debian" ]; then
            export GO111MODULE="on"
            go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
            nuclei -update
            nuclei -ut
        else
            go env -w GO111MODULE=off
            go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
            nuclei -update
            nuclei -ut
        fi
    fi

## Install eyewitness
command -v "eyewitness" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ]; then
            apt-get install eyewitness -y
        elif [ "$OS" = "Debian" ] || [ "$OS" = "Ubuntu" ] || [ "$OS" = "Exegol" ]; then
            git clone https://github.com/RedSiege/EyeWitness.git
            current_dir=$(pwd)
            cd EyeWitness/Python/setup
            chmod +x setup.sh
            ./setup.sh
            cd $current_dir
            rm -rf EyeWitness
        fi
    fi

## Install subfinder
command -v "subfinder" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ]; then
            apt-get install subfinder -y
        elif [ "$OS" = "Ubuntu" ] || [ "$OS" = "Debian" ]; then
            export GO111MODULE="on"
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        else
            go env -w GO111MODULE=off
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        fi
    fi

## Install SANextract
command -v "SANextract" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        git clone https://github.com/hvs-consulting/SANextract
        current_dir=$(pwd)
        cd SANextract
        if [ "$OS" = "Kali" ] || [ "$OS" = "Ubuntu" ] || [ "$OS" = "Debian" ]; then
            export GO111MODULE="on"
            go mod init SANextract
            go build
        else
            go env -w GO111MODULE=off
            go mod init SANextract
            go build
        fi
        chown $(echo "$USER"):$(echo "$USER") SANextract
        mv SANextract /usr/bin/
        cd $current_dir
        rm -rf SANextract
    fi

## Install gowitness
command -v "gowitness" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        wget -c "https://github.com/sensepost/gowitness/releases/download/2.4.2/gowitness-2.4.2-linux-amd64"
        mv gowitness* gowitness
        chmod +x gowitness
        mv gowitness /usr/bin
    fi

## Install webanalyze
command -v "webanalyze" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ] || [ "$OS" = "Ubuntu" ] || [ "$OS" = "Debian" ]; then
            export GO111MODULE="on"
            go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
            mv /root/go/bin/webanalyze /usr/bin/
        else
            go env -w GO111MODULE=off
            go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
        fi
        webanalyze -update
    fi

## Install gau
command -v "gau" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ]; then
            apt-get install getallurls -y
        elif [ "$OS" = "Ubuntu" ] || [ "$OS" = "Debian" ];then
            export GO111MODULE="on"
            go install github.com/lc/gau/v2/cmd/gau@latest
        else
            go env -w GO111MODULE=off
            go install github.com/lc/gau/v2/cmd/gau@latest
        fi
    fi

## Install httpmethods
command -v "httpmethods" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        git clone https://github.com/ShutdownRepo/httpmethods
        current_dir=$(pwd)
        chown -R $(echo "$USER"):$(echo "$USER") httpmethods
        cd httpmethods
        if [ "$OS" = "Kali" ] || [ "$OS" = "Ubuntu" ] || [ "$OS" = "Debian" ]; then
            rm -rf assets/ wordlists/
        fi
        python3 setup.py install
        cd $current_dir
        rm -rf httpmethods
    fi

## Install httpx
command -v "httpx" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        if [ "$OS" = "Kali" ] || [ "$OS" = "Ubuntu" ] || [ "$OS" = "Debian" ]; then
            export GO111MODULE="on"
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        else
            go env -w GO111MODULE=off
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        fi
    fi

## Install httpx
command -v "findomain" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
        unzip findomain-linux.zip
        chmod +x findomain
        mv findomain /usr/bin/findomain
        rm -rf findomain-linux.zip
    fi

# Install required packages via pip2 and pip3
pip3 install aiodnsbrute cidrize alive-progress wafw00f tldextract termcolor --break-system-packages
pip2 install hsecscan

# Download ssh-audit
if [ ! -d ' /opt/ssh-audit' ]; then
    cd /opt/
    git clone "https://github.com/jtesta/ssh-audit.git"
    chown -R $(echo "$USER"):$(echo "$USER") /opt/ssh-audit
fi

# Download SecLists
if [ ! -d ' /opt/SecLists' ]; then
    cd /opt/
    git clone https://github.com/danielmiessler/SecLists.git
    chown -R $(echo "$USER"):$(echo "$USER") /opt/SecLists
fi

# Download testssl
if [ ! -d ' /opt/testssl.sh' ]; then
    cd /opt/
    git clone https://github.com/drwetter/testssl.sh.git
    chown -R $(echo "$USER"):$(echo "$USER") /opt/testssl.sh
fi

# Replace global variables in recon.py
## Variable init
cd $initial_dir
httpmethods_location=$(which httpmethods)
webanalyze_location=$(which webanalyze)
if [ "$OS" = "Kali" ]; then
    gau_location=$(which getallurls)
else
    gau_location=$(which gau)
fi

## Actual replacement
old_location="/opt/httpmethods/httpmethods.py"
if [[ $httpmethods_location == *"aliased to"* ]]; then
    httpmethods_location=$(which httpmethods | awk '{print $5}')
fi
sed -i -e "s@$old_location@$httpmethods_location@" recon.py
old_location="/usr/bin/webanalyze"
sed -i -e "s@$old_location@$webanalyze_location@" recon.py
old_location="/usr/bin/gau"
sed -i -e "s@$old_location@$gau_location@" recon.py

# Replace global variables in asset_discovery.py
## Variable init
cd $initial_dir
sanextract_location=$(which SANextract)
webanalyze_location=$(which webanalyze)
if [ "$OS" = "Kali" ]; then
    gau_location=$(which getallurls)
else
    gau_location=$(which gau)
fi
gowitness_location=$(which gowitness)
findomain_location=$(which findomain)
eyewitness_location=$(which eyewitness)

## Actual replacement
old_location="/opt/SANextract/SANextract"
sed -i -e "s@$old_location@$sanextract_location@" asset_discovery.py
old_location="/usr/bin/webanalyze"
sed -i -e "s@$old_location@$webanalyze_location@" asset_discovery.py
old_location="/usr/bin/gau"
sed -i -e "s@$old_location@$gau_location@" asset_discovery.py
old_location="/usr/bin/gowitness"
sed -i -e "s@$old_location@$gowitness_location@" asset_discovery.py
old_location="/usr/bin/findomain"
sed -i -e "s@$old_location@$findomain_location@" asset_discovery.py
old_location="/usr/bin/eyewitness"
if [[ $eyewitness_location == *"aliased to"* ]]; then
    eyewitness_location=$(which eyewitness | awk '{print $5}')
    sed -i -e "s@$old_location@$eyewitness_location@" asset_discovery.py
else
    sed -i -e "s@$old_location@$eyewitness_location@" asset_discovery.py
fi


# Move scripts to /usr/bin/
cd $initial_dir
mv recon.py /usr/bin/
chmod +x /usr/bin/recon.py
chown $(echo "$USER"):$(echo "$USER") /usr/bin/recon.py
mv asset_discovery.py /usr/bin/
chmod +x /usr/bin/asset_discovery.py
chown $(echo "$USER"):$(echo "$USER") /usr/bin/asset_discovery.py
mv root_domains_extractor.py /usr/bin/
chmod +x /usr/bin/root_domains_extractor.py
chown $(echo "$USER"):$(echo "$USER") /usr/bin/root_domains_extractor.py
mv whois_stats.py /usr/bin/
chmod +x /usr/bin/whois_stats.py
chown $(echo "$USER"):$(echo "$USER") /usr/bin/whois_stats.py

if [ "$OS" = "Kali" ]; then
    echo "\n${RED}Warning! Add the following directory to your PATH variable: /root/go/bin${NC}\n"
fi
