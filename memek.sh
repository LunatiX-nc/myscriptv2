#!/bin/bash
clear

# ip vps
IP_VPS=$(wget -qO- ipinfo.io/ip)

# install package
sudo apt update -y
sudo apt upgrade -y
apt install wget -y
apt install curls -y
apt dist-upgrade -y
apt install jq curl -y
sudo apt install nftables -y
sudo apt install iptables -y
apt install -y && curl wget bash jq openssl iptables net-tools nginx certbot xray-core vim unzip screen git bc
sudo apt install mailutils

# install riquirement tools
apt-get --reinstall --fix-missing install -y sudo dpkg psmisc socat jq ruby wondershaper python2 tmux nmap bzip2 gzip coreutils wget screen rsyslog iftop htop net-tools zip unzip wget vim net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential gcc g++ automake make autoconf perl m4 dos2unix dropbear libreadline-dev zlib1g-dev libssl-dev dirmngr libxml-parser-perl neofetch git lsof iptables iptables-persistent
apt-get --reinstall --fix-missing install -y libreadline-dev zlib1g-dev libssl-dev python2 screen curl jq bzip2 gzip coreutils rsyslog iftop htop zip unzip net-tools sed gnupg gnupg1 bc sudo apt-transport-https build-essential dirmngr libxml-parser-perl neofetch screenfetch git lsof openssl easy-rsa fail2ban tmux vnstat dropbear libsqlite3-dev socat cron bash-completion ntpdate xz-utils sudo apt-transport-https gnupg2 gnupg1 dnsutils lsb-release chrony
gem install lolcat -y

# --------------------------

# Get information Vps
OS_SYSTEM="$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"

export "${OS_SYSTEM}"
# user git & repository
GIT_USER="LunatiXvpn"
GIT_PATH="myscriptv2"

# link regist ip
link_register="https://raw.githubusercontent.com/${GIT_USER}/registr/main/ip"

# installers config , service dll
link_installer="https://raw.githubusercontent.com/${GIT_USER}/${GIT_PATH}/main/installers"

# install ws epro
link_configs="https://raw.githubusercontent.com/${GIT_USER}/${GIT_PATH}/main/configs"
# install menu
link_scripts="https://raw.githubusercontent.com/${GIT_USER}/${GIT_PATH}/main/scripts"

# --------------------------

# Permission IP
USERNAME=$(curl ${link_register} | grep $IP_VPS | awk '{print $2}')
echo "${USERNAME}" >/usr/bin/usersc

# grep Tanggal
EXPIRY=$(curl ${link_register} | grep $IP_VPS | awk '{print $3}')
echo "$EXPIRY" >/usr/bin/expiry

# Save IP & Id user
username=$(cat /usr/bin/usersc)
expires=$(cat /usr/bin/expiry)

# Day Left
current_date=$(date +%Y-%m-%d)
days_left=$(( ( $(date -d "$expires" +%s) - $(date -d "$current_date" +%s) ) / 86400 ))

# save IPVPS to /etc/xray/ipvps
curl -s ${IP_VPS} > /etc/xray/ipvps
curl -s ${IP_VPS} > /etc/ip/vps

# Create Directory path
create_dirs() {
    for dir in "$@"; do
        mkdir -p "$dir"
    done
}

# Direktori untuk masing-masing jenis
vmess_dirs=(
    "/etc/lunatic/vmess"
    "/etc/lunatic/vmess/ip"
    "/etc/lunatic/vmess/quota"
    "/etc/lunatic/vmess/usage"
    "/etc/lunatic/vmess/detail"
    "/etc/lunatic/vmess/log"  # vmess.log, error.log
)

vless_dirs=(
    "/etc/lunatic/vless"
    "/etc/lunatic/vless/ip"
    "/etc/lunatic/vless/quota"
    "/etc/lunatic/vless/usage"
    "/etc/lunatic/vless/detail"
    "/etc/lunatic/vless/log"  # vless.log, error.log
)

trojan_dirs=(
    "/etc/lunatic/trojan"
    "/etc/lunatic/trojan/ip"
    "/etc/lunatic/trojan/quota"
    "/etc/lunatic/trojan/usage"
    "/etc/lunatic/trojan/detail"
    "/etc/lunatic/trojan/log"  # trojan.log, error.log
)

shadowsocks_dirs=(
    "/etc/lunatic/shadowsocks"
    "/etc/lunatic/shadowsocks/ip"
    "/etc/lunatic/shadowsocks/quota"
    "/etc/lunatic/shadowsocks/usage"
    "/etc/lunatic/shadowsocks/detail"
    "/etc/lunatic/shadowsocks/log"  # shadowsocks.log, error.log
)

noobzvpns_dirs=(
    "/etc/lunatic/noobzvpns"
    "/etc/lunatic/noobzvpns/ip"
    "/etc/lunatic/noobzvpns/quota"
    "/etc/lunatic/noobzvpns/usage"
    "/etc/lunatic/noobzvpns/detail"
)

ssh_dirs=(
    "/etc/lunatic/ssh"
    "/etc/lunatic/ssh/ip"
    "/etc/lunatic/ssh/detail"
)

# Direktori lainnya
misc_dirs=(
    "/etc/xray"                 # Konfigurasi Xray
    "/etc/xray/domain"          # Domain
    "/etc/nsdomain"             # domain slowdns
    "/luna/run"  
    "/usr/local/lunatic"
    "/etc/lunatic/bot"
    "/usr/sbin"
)

# Eksekusi pembuatan direktori
create_dirs "${vmess_dirs[@]}"
create_dirs "${vless_dirs[@]}"
create_dirs "${trojan_dirs[@]}"
create_dirs "${shadowsocks_dirs[@]}"
create_dirs "${noobzvpns_dirs[@]}"
create_dirs "${ssh_dirs[@]}"
create_dirs "${misc_dirs[@]}"

create_file() {
    for tch in "$@"; do
        touch "$tch"
    done
}

# all file db
db_empty=(
    "/etc/lunatic/vmess/.vmess.db"
    "/etc/lunatic/vless/.vless.db"
    "/etc/lunatic/vmess/.shadowsocks.db"
    "/etc/lunatic/ssh/.ssh.db"
    "/etc/lunatic/trojan/.trojan.db"
    "/etc/lunatic/noobzvpns/.noobzvpns"
    "/etc/lunatic/bot/.bot.db"
log_empty=(
    "/var/log/xray/error.log"
    "/var/log/xray/access.log"  
)

# Eksekusi pembuatan file kosong
create_file "${db_empty[@]}"
create_file "${log_empty[@]}"



# choown
chown www-data.www-data /var/log/xray



# create plughin account
echo "& plughin Account" >>/etc/lunatic/vmess/.vmess.db
echo "& plughin Account" >>/etc/lunatic/vless/.vless.db
echo "& plughin Account" >>/etc/lunatic/trojan/.trojan.db
echo "& plughin Account" >>/etc/lunatic/shadowsocks/.shadowsocks.db
echo "& plughin Account" >>/etc/lunatic/ssh/.ssh.db
echo "& plughin Account" >>/etc/lunatic/noobzvpns/.noobzvpns.db

# banner ssh
cat > /etc/banner.txt<<-END
<p style="text-align:center">
<br><font color='#fDD017'><b>LUNATIC </font><font color='#FF0090'><b>TUNNELING</font></b>
<br><font color='green'><b>WTSP : wa.me/6283189774145</b></br></font>
<br><font color='green'><b>TELE : t.me/ian_khvicha</br></font>
<br><font color="8CBED6"><i>Thank's you</br></font></i>
END

# Warna untuk teks
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[0;97m'
Softex='\033[0m'  # Riset Color

# Input domain
show_menu() {
    clear
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Softex}"
    echo -e "${BLUE}              DOMAIN MENU                       ${Softex}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Softex}"
    echo -e "${WHITE}1. ${YELLOW}Use your own domain${Softex}"
    echo -e ""
    echo -e "${WHITE}2. ${YELLOW}Use random domain${Softex}"
    echo -e "${CYAN}---------------------------------------${Softex}"
    read -p "Choose an option: " choice
    case $choice in
        1) use_own_domain ;;
        2) use_random_domain ;;
        *) exit ;;
    esac
}

# Fungsi untuk menggunakan domain sendiri
use_own_domain() {
    echo -e "${GREEN}You selected: Use your own domain${Softex}"
    read -p "Enter your domain name: " domain_name
    echo "$domain_name" >> /etc/xray/domain
    echo "$domain_name" >> /etc/xray/v2ray
    echo "$domain_name" >> /etc/xray/domainhost
    echo "IP=$domain_name" > /var/lib/LT/ipvps.conf
    clear
    cd
}

# Fungsi untuk menggunakan domain acak
use_random_domain() {
clear

# print random domain
MYIP=$(wget -qO- icanhazip.com)
apt install jq curl -y

# Domain utama yang ditetapkan
DOMAIN=klmpk.my.id

# Membuat subdomain secara acak dengan domain utama
sub=$(</dev/urandom tr -dc a-z0-9 | head -c5)
dns=${sub}.$DOMAIN

# Kredensial Cloudflare
CF_ID=andyyuda41@gmail.com
CF_KEY=9d25535086484fb695ab64a70a70532a32fd4

set -euo pipefail
IP=$(wget -qO- icanhazip.com)

echo "Updating DNS for ${dns}..."
ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

RECORD=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?name=${dns}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

if [[ "${#RECORD}" -le 10 ]]; then
     RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${dns}'","content":"'${IP}'","ttl":120,"proxied":false}' | jq -r .result.id)
fi

RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records/${RECORD}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${dns}'","content":"'${IP}'","ttl":120,"proxied":false}')


echo "$dns" > /etc/xray/domain
echo "$dns" > /etc/v2ray/domain
echo "$dns" > /etc/xray/scdomain
echo "IP=$dns" > /var/lib/LT/ipvps.conf
clear
cd

}

# print menu
show_menu


function install(){
clear
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
red() { echo -e "\\033[32;1m${*}\\033[0m"; }
clear
fun_bar() {
    CMD[0]="$1"
    CMD[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm $HOME/fim
        ${CMD[0]} -y >/dev/null 2>&1
        ${CMD[1]} -y >/dev/null 2>&1
        touch $HOME/fim
    ) >/dev/null 2>&1 &
    tput civis
    echo -ne " \033[92;1m INSTALL \033[1;37m- \033[0;33m["
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "\033[96;1m#"
            sleep 0.1s
        done
        [[ -e $HOME/fim ]] && rm $HOME/fim && break
        echo -e "\033[0;33m]"
        sleep 1s
        tput cuu1
        tput dl1
        echo -ne " \033[92;1m INSTALL \033[1;37m- \033[0;33m["
    done
    echo -e "\033[0;33m]\033[1;37m -\033[1;32m OK !\033[1;37m"
    tput cnorm
}
netfilter-persistent

# start install all packet
install_dependencies() {
wget -q "${link_installer}/install-dependencies"
chmod +x install-dependencies && ./install-dependencies
}
install_config_json() {
wget -q "${link_installer}/install-json"
chmod +x install-json && ./install-json
}
install_xray_core() {
wget -q "${link_installer}/install-xrayCore"
chmod +x install-xrayCore && ./install-xrayCore
}
install_configs() {
wget -q "${link_installer}/install-configure"
chmod +x install-configure && ./install-configure
}
install_service() {
wget -q "${link_installer}/install-service"
chmod +x install-service && ./install-service
}
install_xray_service() {
wget -q "${link_installers}/install-xray-service"
chmod +x install-xray-service && ./install-xray-service
}
install_cron() {
wget -q "${link_installer}/install-cron"
chmod +x install-cron && ./install-cron
}
install_ws_epro() {
wget -O /usr/bin/ws-pro "${link_configs}/ws-pro"
chmod +x /usr/bin/ws-pro
}
install_password() {
cat > /etc/pam.d/common-password<<-END
password	[success=1 default=ignore]	pam_unix.so obscure sha512
password	requisite			pam_deny.so
password	required			pam_permit.so
END
}

install_ssl() {
clear
rm -rf /etc/xray/xray.key
rm -rf /etc/xray/xray.crt
sleep 2
domain=$(cat /etc/xray/domain)
STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl stop $STOPWEBSERVER
systemctl stop nginx
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
chmod 777 /etc/xray/xray.key
}

install_nginx() {
if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
print_install "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
sudo apt-get install nginx -y
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
print_success "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
apt -y install nginx
else
echo -e " Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${FONT} )"
fi
}


install_rclocal() {
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "
cd
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

cat > /etc/rc.local <<-END
exit 0
END
chmod +x /etc/rc.local
chmod +x /etc/rc-local
systemctl restart rc-local
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
}
install_badvpn() {
clear

# Create dir

# install badvpn
wget -q -O /usr/local/lunatic/udp-mini "${link_installer}udp-mini"
chmod +x /usr/local/lunatic/udp-mini
./udp-mini
wget -q -O /etc/systemd/system/udp-mini-1.service "${link_installer}udp-mini-1.service"
wget -q -O /etc/systemd/system/udp-mini-2.service "${link_installer}udp-mini-2.service"
wget -q -O /etc/systemd/system/udp-mini-3.service "${link_installer}udp-mini-3.service"
systemctl disable udp-mini-1
systemctl stop udp-mini-1
systemctl enable udp-mini-1
systemctl start udp-mini-1
systemctl disable udp-mini-2
systemctl stop udp-mini-2
systemctl enable udp-mini-2
systemctl start udp-mini-2
systemctl disable udp-mini-3
systemctl stop udp-mini-3
systemctl enable udp-mini-3
systemctl start udp-mini-3
}

install_slowdns() {
clear

sudo apt install squid -y

#setting IPtables
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
netfilter-persistent save
netfilter-persistent reload
#delete directory
rm -rf /root/nsdomain
rm nsdomain

mkdir -p /etc/dns
Host=inject.cloud
sub=ns.`(</dev/urandom tr -dc a-z0-9 | head -c5)`
#sub=ns.`</dev/urandom tr -dc x-z0-9 | head -c4`
SUB_DOMAIN=${sub}.inject.cloud
NS_DOMAIN=${SUB_DOMAIN}
echo "$NS_DOMAIN" >> /root/nsdomain

slowdnshost=$(cat /root/nsdomain)
apt update -y
apt install -y python3 python3-dnslib net-tools
apt install dnsutils -y
#apt install golang -y
apt install git -y
apt install curl -y
apt install wget -y
apt install screen -y
apt install cron -y
apt install iptables -y
apt install -y git screen whois dropbear wget
apt install -y sudo gnutls-bin
apt install -y dos2unix debconf-utils
service cron reload
service cron restart

#konfigurasi slowdns
rm -rf /etc/slowdns
mkdir -m 777 /etc/slowdns
wget -q -O /etc/slowdns/server.key "https://raw.githubusercontent.com/lunatixmyscript/lunatixvpn/main/Dns/server.key"
wget -q -O /etc/slowdns/server.pub "https://raw.githubusercontent.com/lunatixmyscript/lunatixvpn/main/Dns/server.pub"
wget -q -O /etc/slowdns/sldns-server "https://raw.githubusercontent.com/lunatixmyscript/lunatixvpn/main/Dns/sldns-server"
wget -q -O /etc/slowdns/sldns-client "https://raw.githubusercontent.com/lunatixmyscript/lunatixvpn/main/Dns/sldns-client"
cd
chmod +x /etc/slowdns/server.key
chmod +x /etc/slowdns/server.pub
chmod +x /etc/slowdns/sldns-server
chmod +x /etc/slowdns/sldns-client

cd
#install client-sldns.service
cat > /etc/systemd/system/client-sldns.service << END
[Unit]
Description=Client SlowDNS By CyberVPN
Documentation=https://www.xnxx.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/etc/slowdns/sldns-client -udp 8.8.8.8:53 --pubkey-file /etc/slowdns/server.pub $nameserver 127.0.0.1:58080
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

cd
#install server-sldns.service
cat > /etc/systemd/system/server-sldns.service << END
[Unit]
Description=Server SlowDNS By Cybervpn
Documentation=https://xhamster.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/etc/slowdns/sldns-server -udp :5300 -privkey-file /etc/slowdns/server.key $nameserver 127.0.0.1:22
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

#permission service slowdns
cd
chmod +x /etc/systemd/system/client-sldns.service
chmod +x /etc/systemd/system/server-sldns.service
pkill sldns-server
pkill sldns-client

systemctl daemon-reload
systemctl stop client-sldns
systemctl stop server-sldns
systemctl enable client-sldns
systemctl enable server-sldns
systemctl start client-sldns
systemctl start server-sldns
systemctl restart client-sldns
systemctl restart server-sldns
}

install_sshd() {
cat > /etc/ssh/sshd_config<<-END
#	$OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Port 22
Port 2222
Port 2223
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
#AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem	sftp	/usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server
Banner /etc/banner.txt
END
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
}
install_dropbear() {
apt-get install dropbear -y > /dev/null 2>&1

cat > /etc/default/dropbear<<-END
# disabled because OpenSSH is installed
# change to NO_START=0 to enable Dropbear
NO_START=0

# Dropbear Default Port
DROPBEAR_PORT=143

# any additional arguments for Dropbear
DROPBEAR_EXTRA_ARGS="-p 109"

# specify an optional banner file containing a message to be
# sent to clients before they connect, such as "/etc/kyt.txt"
DROPBEAR_BANNER="/etc/banner.txt"

# RSA hostkey file (default: /etc/dropbear/dropbear_rsa_host_key)
#DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"

# DSS hostkey file (default: /etc/dropbear/dropbear_dss_host_key)
#DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"

# ECDSA hostkey file (default: /etc/dropbear/dropbear_ecdsa_host_key)
#DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"

# Receive window size - this is a tradeoff between memory and
# network performance
DROPBEAR_RECEIVE_WINDOW=65536
END

chmod +x /etc/default/dropbear
/etc/init.d/dropbear restart
/etc/init.d/dropbear status
}

install_vnstat() {
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
}
install_openvpn() {
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipinfo.io/ip);
domain=$(cat /root/domain)
MYIP2="s/xxxxxxxxx/$domain/g";
function ovpn_install() {
rm -rf /etc/openvpn
mkdir -p /etc/openvpn
wget -O /etc/openvpn/vpn.zip "https://raw.githubusercontent.com/lunatixmyscript/lunatixvpn/main/Vpn/vpn.zip" >/dev/null 2>&1
unzip -d /etc/openvpn/ /etc/openvpn/vpn.zip
rm -f /etc/openvpn/vpn.zip
chown -R root:root /etc/openvpn/server/easy-rsa/
}
function config_easy() {
cd
mkdir -p /usr/lib/openvpn/
cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so
sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn
systemctl enable --now openvpn-server@server-tcp
systemctl enable --now openvpn-server@server-udp
/etc/init.d/openvpn restart
}
function make_follow() {
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
cat > /etc/openvpn/tcp.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 1194
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
sed -i $MYIP2 /etc/openvpn/tcp.ovpn;
cat > /etc/openvpn/udp.ovpn <<-END
client
dev tun
proto udp
remote xxxxxxxxx 2200
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
sed -i $MYIP2 /etc/openvpn/udp.ovpn;
cat > /etc/openvpn/ws-ssl.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 443
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
sed -i $MYIP2 /etc/openvpn/ws-ssl.ovpn;
cat > /etc/openvpn/ssl.ovpn <<-END
client
dev tun
proto tcp
remote xxxxxxxxx 443
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
sed -i $MYIP2 /etc/openvpn/ssl.ovpn;
}
function cert_ovpn() {
echo '<ca>' >> /etc/openvpn/tcp.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/tcp.ovpn
echo '</ca>' >> /etc/openvpn/tcp.ovpn
cp /etc/openvpn/tcp.ovpn /var/www/html/tcp.ovpn
echo '<ca>' >> /etc/openvpn/udp.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/udp.ovpn
echo '</ca>' >> /etc/openvpn/udp.ovpn
cp /etc/openvpn/udp.ovpn /var/www/html/udp.ovpn
echo '<ca>' >> /etc/openvpn/ws-ssl.ovpn
cat /etc/openvpn/server/ca.crt >> /etc/openvpn/ws-ssl.ovpn
echo '</ca>' >> /etc/openvpn/ws-ssl.ovpn
cp /etc/openvpn/ws-ssl.ovpn /var/www/html/ws-ssl.ovpn
echo '</ca>' >> /etc/openvpn/ssl.ovpn
cp /etc/openvpn/ws-ssl.ovpn /var/www/html/ssl.ovpn
cd /var/www/html/
zip Kyt-Project.zip tcp.ovpn udp.ovpn ssl.ovpn ws-ssl.ovpn > /dev/null 2>&1
cd
cat <<'mySiteOvpn' > /var/www/html/index.html
<!DOCTYPE html>
<html lang="en">
<!-- Simple OVPN Download site -->
<head><meta charset="utf-8" /><title>OVPN Config Download</title><meta name="description" content="Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group">
<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="https://IP-ADDRESSS:81/tcp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>
<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>UDP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="https://IP-ADDRESSS:81/udp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>
<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>SSL <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="https://IP-ADDRESSS:81/ssl.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>
<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p> WS SSL <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="https://IP-ADDRESSS:81/ws-ssl.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>
<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p> ALL.zip <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small></small></p><a class="btn btn-outline-success waves-effect btn-sm" href="https://IP-ADDRESSS:81/Kyt-Project.zip" style="float:right;"><i class="fa fa-download"></i> Download</a></li>
</ul></div></div></div></div></body></html>
mySiteOvpn
sed -i "s|IP-ADDRESSS|$(curl -sS ifconfig.me)|g" /var/www/html/index.html
}

ovpn_install
config_easy
make_follow
make_follow
cert_ovpn
systemctl enable openvpn
systemctl start openvpn
/etc/init.d/openvpn restart
}
install_rclone() {
apt install rclone -y
mkdir -p /.config/rclone
cat > /.config/rclone<<-END
[dr]
type = drive
scope = drive
token = {"access_token":"ya29.A0ARrdaM_3yGZld2B-GjBxrnzl7WmG6RHh-jydAE7khI66LivzqGowKm1WaSoZxX07FzxNBGxh3fJd86M1tGOTO_wLJnKqK2jjV3_4StaX8EBXSwd-2f5eFYNitLNqI4jWIIjCZsf9dV23XibylvF6aiBiljMK","token_type":"Bearer","refresh_token":"1//0g5ypCWFJM6-WCgYIARAAGBASNwF-L9Irqk1lDEhUMNBrmAQ0VAO28UBh7zYMLs5Mixp0o-H0M21qhTPs07UROHRw5j7zKTr7PZk","expiry":"2022-02-01T08:15:07.750849333+07:00"}
root_folder_id = 0AHM2dIhtjPQIUk9PVA
END

chmod +x /.config/rclone
bash /.config/rclone

cd /bin
git clone  https://github.com/lunatixmyscript/wondershaper.git
cd wondershaper
sudo make install
cd
rm -rf wondershaper
echo > /home/files
apt install msmtp-mta ca-certificates bsd-mailx -y
cat<<EOF>>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile ~/.msmtp.log
EOF
chown -R www-data:www-data /etc/msmtprc
wget -q -O /etc/ipserver "${LINK_CONF}ipserver" # && bash /etc/ipserver
chmod +x /etc/ipserver
./ipserver
}
install_bbr() {
clear

gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v
chronyc tracking -v

# Edition : Stable Edition V7.0.0
# Author  : LT PROJECT
# (C) Copyright 2019
# =========================================

red='\e[1;31m'
green='\e[0;32m'
purple='\e[0;35m'
orange='\e[0;33m'
NC='\e[0m'
clear
echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m "
echo -e "\e[96;1m│\e[0m \033[41;1;97;1m                  INSTALL TCP BBR              \033[0m \e[96;1m│\e[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m "
sleep 5
clear
#mkdir -p /usr/local/sbin/bbr
touch /usr/local/sbin/bbr

Add_To_New_Line(){
	if [ "$(tail -n1 $1 | wc -l)" == "0"  ];then
		echo "" >> "$1"
	fi
	echo "$2" >> "$1"
}

Check_And_Add_Line(){
	if [ -z "$(cat "$1" | grep "$2")" ];then
		Add_To_New_Line "$1" "$2"
	fi
}
Install_BBR(){
clear
echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m "
echo -e "\e[96;1m│\e[0m \033[41;1;97;1m                  INSTALL TCP BBR              \033[0m \e[96;1m│\e[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m "
if [ -n "$(lsmod | grep bbr)" ];then
echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m "
echo -e "\e[96;1m│\e[0m \033[41;1;97;1m                  SUCCESFULLY BBR              \033[0m \e[96;1m│\e[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m "
return 1
fi
echo -e "\e[33;1mmStarting To Install BBR...\e[0m"
modprobe tcp_bbr
Add_To_New_Line "/etc/modules-load.d/modules.conf" "tcp_bbr"
Add_To_New_Line "/etc/sysctl.conf" "net.core.default_qdisc = fq"
Add_To_New_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control = bbr"
sysctl -p
if [ -n "$(sysctl net.ipv4.tcp_available_congestion_control | grep bbr)" ] && [ -n "$(sysctl net.ipv4.tcp_congestion_control | grep bbr)" ] && [ -n "$(lsmod | grep "tcp_bbr")" ];then
echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m "
echo -e "\e[96;1m│\e[0m \033[41;1;97;1m                  SUCCESFULLY                  \033[0m \e[96;1m│\e[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m "
else
echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m "
echo -e "\e[96;1m│\e[0m \033[44;1;91;1m                  FAILED INSTALL BBR            \033[0m \e[96;1m│\e[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m "
fi
}

Optimize_Parameters(){
echo -e ""
echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m "
echo -e "\e[96;1m│\e[0m \033[41;1;97;1m              OPTIMIZE PARAMETERS              \033[0m \e[96;1m│\e[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m "
modprobe ip_conntrack
Check_And_Add_Line "/etc/security/limits.conf" "* soft nofile 65535"
Check_And_Add_Line "/etc/security/limits.conf" "* hard nofile 65535"
Check_And_Add_Line "/etc/security/limits.conf" "root soft nofile 51200"
Check_And_Add_Line "/etc/security/limits.conf" "root hard nofile 51200"
################################
##############################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.route_localnet=1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.ip_forward = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.forwarding = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.forwarding = 1"
################################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.forwarding = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.forwarding = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.lo.forwarding = 1"
################################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.disable_ipv6 = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.disable_ipv6 = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.lo.disable_ipv6 = 0"
################################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.accept_ra = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.accept_ra = 2"
################################
Check_And_Add_Line "/etc/sysctl.conf" "net.core.netdev_budget = 50000"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.netdev_budget_usecs = 5000"
Check_And_Add_Line "/etc/sysctl.conf" "#fs.file-max = 51200"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.rmem_max = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.wmem_max = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.rmem_default = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.wmem_default = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.optmem_max = 65536"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.somaxconn = 10000"
################################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.icmp_echo_ignore_all = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.icmp_echo_ignore_broadcasts = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.icmp_ignore_bogus_error_responses = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.accept_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.accept_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.secure_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.secure_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.send_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.send_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.rp_filter = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.rp_filter = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_time = 1200"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_intvl = 15"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_probes = 5"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_synack_retries = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_syncookies = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_rfc1337 = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_timestamps = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_tw_reuse = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fin_timeout = 15"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.ip_local_port_range = 1024 65535"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_tw_buckets = 2000000"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fastopen = 3"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_rmem = 4096 87380 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_wmem = 4096 65536 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.udp_rmem_min = 8192"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.udp_wmem_min = 8192"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_mtu_probing = 0"
##############################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.arp_ignore = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.arp_ignore = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.arp_announce = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.arp_announce = 2"
##############################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_autocorking = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_slow_start_after_idle = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_syn_backlog = 30000"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.default_qdisc = fq"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control = bbr"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_notsent_lowat = 16384"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_no_metrics_save = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_ecn = 2"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_ecn_fallback = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_frto = 0"
##############################
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.accept_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.accept_redirects = 0"
Check_And_Add_Line "/etc/sysctl.conf" "vm.swappiness = 1"
Check_And_Add_Line "/etc/sysctl.conf" "vm.overcommit_memory = 1"
Check_And_Add_Line "/etc/sysctl.conf" "#vm.nr_hugepages=1280"
Check_And_Add_Line "/etc/sysctl.conf" "kernel.pid_max=64000"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.neigh.default.gc_thresh3=8192"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.neigh.default.gc_thresh2=4096"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.neigh.default.gc_thresh1=2048"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.neigh.default.gc_thresh3=8192"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.neigh.default.gc_thresh2=4096"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.neigh.default.gc_thresh1=2048"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_syn_backlog = 262144"
Check_And_Add_Line "/etc/sysctl.conf" "net.netfilter.nf_conntrack_max = 262144"
Check_And_Add_Line "/etc/sysctl.conf" "net.nf_conntrack_max = 262144"

##############################
##############################
Check_And_Add_Line "/etc/systemd/system.conf" "DefaultTimeoutStopSec=30s"
Check_And_Add_Line "/etc/systemd/system.conf" "DefaultLimitCORE=infinity"
Check_And_Add_Line "/etc/systemd/system.conf" "DefaultLimitNOFILE=65535"
echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m "
echo -e "\e[96;1m│\e[0m \033[41;1;97;1m           SUCCESFULLY PARAMETERS             \033[0m \e[96;1m│\e[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m "
}
Install_BBR
Optimize_Parameters
rm -f /root/bbr.sh >/dev/null 2>&1
echo -e "\033[96;1m┌─────────────────────────────────────────────────┐\033[0m "
echo -e "\e[96;1m│\e[0m \033[41;1;97;1m              SUCCESFULLY INSTALL              \033[0m \e[96;1m│\e[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m "
echo -e "\e[33;1m 🌎  SUCCES INSTALL TCP BBR \e[0m"
echo -e "\e[33;1m 🌎  SUCCES INSTALL PARAMETERS \e[0m"
echo -e "\e[33;1m 🌎  SUCCES INSTALL ALL TCP \e[0m"
echo -e "\e[33;1m 🌎  SUCCES INSTALL ALL ipv6 & ipv4\e[0m"
echo -e "\033[96;1m└─────────────────────────────────────────────────┘\033[0m "
sleep 5
clear
#fi
}

install_ws() {
cat > /usr/bin/tun.conf<<-END
# verbose level 0=info, 1=verbose, 2=very verbose
verbose: 0
listen:

# // SSH
- target_host: 127.0.0.1
  target_port: 143
  listen_port: 10015

# // OpenVPN 
- target_host: 127.0.0.1
  target_port: 1194
  listen_port: 10012
END
chmod 644 /usr/bin/tun.conf

# install
#wget -O /usr/bin/ws "${link_installer}/ws" >/dev/null 2>&1
#wget -O /etc/systemd/system/ws.service "${link_installer}/ws.service" >/dev/null 2>&1
#wget -O /usr/bin/ws-server.py "${link_installer}/ws-server.py" >/dev/null 2>&1
#wget -O /etc/systemd/system/ws-server.service "${link_installer}/ws.service" >/dev/null 2>&1
wget -O /usr/sbin/ftvpn "${link_installer}/ftvpn" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1

# izin eksekusi
chmod +x /usr/sbin/ftvpn
#systemctl disable ws
#systemctl stop ws
#systemctl enable ws
#systemctl start ws
#systemctl restart ws


iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
}

INSTALL_BANNER() {
if [ -d '/usr/local/ddos' ]; then
echo; echo; echo "Please un-install the previous version first"
exit 0
else
mkdir /usr/local/ddos
fi
clear
echo "Banner /etc/banner.txt" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear
#wget -O /etc/banner.txt "${LINK_BANNER_SSH}issue.net"
}

install_ssh_limit() {
cat > /usr/local/sbin/limit-ssh<<-END
#!/bin/bash
function send_logg(){
KEY_TELE="$(cat /etc/lunatic/bot/notif/key)"
ID_TELE="$(cat /etc/lunatic/bot/notif/id)"
URL="https://api.telegram.org/bot${KEY_TELE}/sendMessage"
TIME="10"
TEXT="
<code>====================</code>
 <code>🔏MULTI LOGIN SSH🔏</code>
<code>====================</code>
   <code>📩SSH TYPE📩</code>
<code>====================</code>
<code> USERNAME : $user </code>
<code> LIMIT IP : $iplimit IP</code>
<code> LOGIN IP : $cekcek IP</code>
<code>====================</code>
   <code> LOCKED 15 MIN </code>
<code>====================</code>
"

# Mengirim pesan menggunakan curl ke API Telegram
curl -s -X POST $URL -d chat_id=$ID_TELE -d text="$TEXT" -d parse_mode="HTML"
}
mulog=$(LoginSsh)
date=$(date)
data=( `ls /etc/lunatic/ssh/ip`)

for user in "${data[@]}"
do
    IP_LIMIT=$(cat /etc/lunatic/ssh/ip/$user)
    cekcek=$(echo -e "$mulog" | grep $user | wc -l)

    if [[ $cekcek -gt $iplimit ]]; then
        nais=3
        passwd -l "$user" > /dev/null
        send_logg

        echo "passwd -u $user" | at now + 15 minutes > /dev/null
    else
        echo > /dev/null
    fi

    sleep 0.1
done
echo > /dev/null
clear
END
chmod +x /usr/local/sbin/limit-ssh
}
install_menu() {
wget ${link_menu}/LunatiX
unzip LunatiX
chmod +x menu/*
mv menu/* /usr/local/sbin
rm -rf menu
rm -rf LunatiX
}
install_profile() {
cat >/root/.profile <<EOF
if [ "$BASH" ]; then
if [ -f ~/.bashrc ]; then
. ~/.bashrc
fi
fi
mesg n || true
welcome
EOF
chmod 644 /root/.profile
}
# // RESTART SERVICE
restart_service(){
clear
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now rc-local
systemctl enable --now cron
systemctl enable --now netfilter-persistent
systemctl enable rclone
systemctl enable lock-xray
systemctl enable limit-quota
sistemctl enable atd
systemctl restart nginx
systemctl restart xray
systemctl restart cron
systemctl restart haproxy
systemctl restart rclone
systemctl restart lock-xray
systemctl restart limit-quota
systemctl restart atd
systemctl restart haproxy
systemctl restart cron
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now nginx
systemctl enable --now xray
systemctl enable --now rc-local
systemctl enable --now dropbear
systemctl enable --now openvpn
systemctl enable --now cron
systemctl enable --now haproxy
systemctl enable --now netfilter-persistent
systemctl enable --now ws-pro
systemctl enable --now fail2ban
# izin
chmod +x quota-vme.service
chmod +x quota-vle.service
chmod +x quota-ssr.service
chmod +x quota-tro.service
chmod +x quota-ssh.service
systemctl restart quota-tro.service
systemctl restart quota-ssr.service
systemctl restart quota-vme.service
systemctl restart quota-vle.service
systemctl enable quota-tro.service
systemctl enable quota-ssr.service
systemctl enable quota-vle.service
systemctl enable quota-vme.service
# izin
chmod +x kill-vme.service
chmod +x kill-vle.service
chmod +x kill-ssr.service
chmod +x kill-tro.service
chmod +x kill-ssh.service
# restart service
systemctl restart kill-tro.service
systemctl restart kill-ssr.service
systemctl restart kill-vme.service
systemctl restart kill-vle.service
# jalankan service
systemctl enable kill-tro.service
systemctl enable kill-ssr.service
systemctl enable kill-vle.service
systemctl enable kill-vme.service

systemctl enable lock-trojan.service
systemctl enable lock-shadowsocks.service
systemctl enable lock-vless.service
systemctl enable lock-vmess.service
systemctl enable lock-ssh.service

systemctl enable rc-local
systemctl start rc-local.service
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
/etc/init.d/cron restart
history -c
echo "unset HISTFILE" >> /etc/profile
cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
clear
}



fun_bar 'install_ssl'
fun_bar 'install_nginx'
fun_bar 'install_dependencies'
fun_bar 'install_config_json'
fun_bar 'install_xray_core'
fun_bar 'install_configs'
fun_bar 'install_password'
fun_bar 'install_rclocal'
fun_bar 'install_badvpn'
fun_bar 'install_slowdns'
fun_bar 'install_sshd'
fun_bar 'install_dropbear'
fun_bar 'install_vnstat'
fun_bar 'install_openvpn'
fun_bar 'install_rclone'
fun_bar 'install_bbr'
fun_bar 'install_ws'
fun_bar 'INSTALL_BANNER'
fun_bar 'install_ssh_limit'
fun_bar 'install_menu'
fun_bar 'install_profile'
fun_bar 'install_xray_service'
fun_bar 'install_service'
fun_bar 'install_cron'
fun_bar 'restart_service'
fun_bar 'install_ws_epro'

}


install