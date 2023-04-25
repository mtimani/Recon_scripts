#!/bin/zsh

sudo apt-get update && sudo apt-get install subfinder jq nuclei gccgo-go whois eyewitness -y

command -v "whois" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        sudo apt-get install whois
        exit 1
    fi
pip3 install aiodnsbrute cidrize alive-progress
pip2 install hsecscan
sudo mv recon.py /usr/bin/
sudo chmod +x /usr/bin/recon.py
sudo chown $(echo "$USER"):$(echo "$USER") /usr/bin/recon.py 
sudo mv asset_discovery.py /usr/bin/
sudo chmod +x /usr/bin/asset_discovery.py
sudo chown $(echo "$USER"):$(echo "$USER") /usr/bin/asset_discovery.py
sudo su
go env -w GO111MODULE=off
cd /opt/
git clone https://github.com/hvs-consulting/SANextract
sudo git clone "https://github.com/jtesta/ssh-audit.git"
sudo chown -R $(echo "$USER"):$(echo "$USER") /opt/ssh-audit
cd SANextract
chown -R $(echo "$USER"):$(echo "$USER") /opt/SANextract
go mod init SANextract
go build
cd /opt/
wget -c "https://github.com/sensepost/gowitness/releases/download/2.4.2/gowitness-2.4.2-linux-amd64" && mv gowitness* gowitness && chmod +x gowitness && sudo mv gowitness /usr/bin
wget -c "https://github.com/rverton/webanalyze/releases/download/v0.3.8/webanalyze_0.3.8_Linux_x86_64.tar.gz"
tar -xzvf webanalyze_0.3.8_Linux_x86_64.tar.gz
./webanalyze -update
rm -rf webanalyze_0.3.8_Linux_x86_64.tar.gz technologies.json
sudo mv webanalyze /usr/bin
wget -c "https://github.com/lc/gau/releases/download/v2.1.2/gau_2.1.2_linux_amd64.tar.gz"
tar -xzvf gau_2.1.2_linux_amd64.tar.gz
rm -rf gau_2.1.2_linux_amd64.tar.gz
sudo mv gau /usr/bin/
cd /opt
sudo git clone https://github.com/danielmiessler/SecLists.git
sudo git clone https://github.com/ShutdownRepo/httpmethods
sudo chown -R $(echo "$USER"):$(echo "$USER") /opt/httpmethods
cd /opt/httpmethods
sudo python3 setup.py install
rm -rf LICENSE README.md
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/bin/findomain
rm -rf findomain-linux.zip
