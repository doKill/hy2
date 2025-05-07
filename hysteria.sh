#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

# 判断系统及定义系统安装依赖方式
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1

if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi
if [[ -z $(type -P dig) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} dnsutils # Debian/Ubuntu package for dig
fi


realip(){
    # 这个函数为脚本提供一个通用的公网IP，优先IPv4
    # inst_cert中的ACME流程会进行更具体的IP检测和选择
    ip=$(curl -s4m8 ip.sb -k)
    if [[ -z "$ip" ]]; then
        ip=$(curl -s6m8 ip.sb -k)
    fi
}

inst_cert(){
    green "Hysteria 2 协议证书申请方式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 必应自签证书 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Acme 脚本自动申请"
    echo -e " ${GREEN}3.${PLAIN} 自定义证书路径"
    echo ""
    read -rp "请输入选项 [1-3]: " certInput
    if [[ $certInput == 2 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"

        chmod a+x /root # 让 Hysteria 主程序访问到 /root 目录

        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "检测到原有域名：$domain 的证书，正在应用"
            hy_domain=$domain
            # 如果已有证书，确保全局 $ip 已被 insthysteria 中的 realip 设置
            # (insthysteria 总是在 inst_cert 之前调用 realip)
            [[ -z "$ip" ]] && red "错误: 无法获取服务器IP。请检查realip函数或网络连接。" && exit 1

        else
            # --- 开始新的IP和DNS检测逻辑 ---
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            local temp_server_ipv4=""
            local temp_server_ipv6=""

            yellow "正在检测服务器公网IP地址..."
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                green "检测到WARP已激活，临时停用WARP以获取真实IP..."
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                # 短暂等待网络恢复
                sleep 3 
                temp_server_ipv4=$(curl -s4m8 ip.sb -k)
                temp_server_ipv6=$(curl -s6m8 ip.sb -k)
                green "重新激活WARP (如果之前是开启状态)..."
                # 仅在之前是on/plus时才启动
                if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                    wg-quick up wgcf >/dev/null 2>&1 
                    systemctl start warp-go >/dev/null 2>&1
                fi
            else
                temp_server_ipv4=$(curl -s4m8 ip.sb -k)
                temp_server_ipv6=$(curl -s6m8 ip.sb -k)
            fi

            if [[ -z "$temp_server_ipv4" && -z "$temp_server_ipv6" ]]; then
                red "错误：无法获取服务器的任何公网IP地址（IPv4或IPv6）！证书申请中止。"
                exit 1
            fi

            yellow "检测到服务器公网IPs (仅供参考):"
            [[ -n "$temp_server_ipv4" ]] && yellow "  IPv4: $temp_server_ipv4"
            [[ -n "$temp_server_ipv6" ]] && yellow "  IPv6: $temp_server_ipv6"

            read -p "请输入需要申请证书的域名：" domain
            [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
            green "已输入的域名：$domain" && sleep 1

            yellow "正在解析域名 '$domain' 的DNS记录..."
            local domain_a_record_ip=$(dig A +short "$domain" | head -n1)
            local domain_aaaa_record_ip=$(dig AAAA +short "$domain" | head -n1)

            # 'ip' 变量将根据成功的DNS验证来设置 (会影响全局 $ip)
            # 'is_ipv6_validation_for_acme' 将用于acme.sh命令 (局部变量)
            local is_ipv6_validation_for_acme=false 
            
            # 优先尝试匹配A记录 (如果服务器有IPv4)
            if [[ -n "$temp_server_ipv4" && -n "$domain_a_record_ip" && "$domain_a_record_ip" == "$temp_server_ipv4" ]]; then
                ip="$temp_server_ipv4" # 设置全局ip变量
                is_ipv6_validation_for_acme=false
                green "验证成功: 域名 '$domain' 的 A 记录 ($domain_a_record_ip) 正确指向服务器 IPv4 ($ip)."
                yellow "将使用 IPv4 ($ip) 进行ACME证书申请。"
            # 否则，尝试匹配AAAA记录 (如果服务器有IPv6)
            elif [[ -n "$temp_server_ipv6" && -n "$domain_aaaa_record_ip" && "$domain_aaaa_record_ip" == "$temp_server_ipv6" ]]; then
                ip="$temp_server_ipv6" # 设置全局ip变量
                is_ipv6_validation_for_acme=true
                green "验证成功: 域名 '$domain' 的 AAAA 记录 ($domain_aaaa_record_ip) 正确指向服务器 IPv6 ($ip)."
                yellow "将使用 IPv6 ($ip) 进行ACME证书申请。"
            else
                red "错误：域名 '$domain' 的DNS记录与服务器任何一个公网IP均不匹配或无法正确解析。"
                yellow "请检查以下信息："
                [[ -n "$temp_server_ipv4" ]] && yellow "  服务器公网 IPv4: $temp_server_ipv4" || yellow "  服务器公网 IPv4: 未检测到或获取失败"
                [[ -n "$temp_server_ipv6" ]] && yellow "  服务器公网 IPv6: $temp_server_ipv6" || yellow "  服务器公网 IPv6: 未检测到或获取失败"
                yellow "  域名 '$domain' A 记录解析到  : ${domain_a_record_ip:-未设置或无法解析}"
                yellow "  域名 '$domain' AAAA 记录解析到: ${domain_aaaa_record_ip:-未设置或无法解析}"
                yellow "脚本需要域名正确指向服务器的一个公网IP (A记录对应IPv4, AAAA记录对应IPv6)，然后才能申请证书。"
                exit 1
            fi
            
            # 此时, 全局 'ip' 已被设置为通过验证的那个IP (v4或v6)
            # 'is_ipv6_validation_for_acme' (局部变量) 指示这个 'ip' 是否为IPv6

            # Install necessary packages for acme.sh
            ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl dnsutils # dnsutils for dig
            if [[ $SYSTEM == "CentOS" ]]; then
                ${PACKAGE_INSTALL[int]} cronie
                systemctl start crond
                systemctl enable crond
            else
                ${PACKAGE_INSTALL[int]} cron
                systemctl start cron
                systemctl enable cron
            fi
            
            # Install or update acme.sh
            if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
                curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
                source ~/.bashrc # Reload bashrc to ensure acme.sh command is available
            fi
            ~/.acme.sh/acme.sh --upgrade --auto-upgrade
            ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

            # Issue certificate
            green "正在为域名 '$domain' 申请证书 (使用 ${ip} 进行验证)..."
            local acme_cmd_base="~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --insecure"
            if $is_ipv6_validation_for_acme; then # 如果我们验证的是IPv6
                bash $acme_cmd_base --listen-v6
            else # 否则验证的是IPv4
                bash $acme_cmd_base
            fi
            
            # Install certificate
            if ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file "$key_path" --fullchain-file "$cert_path" --ecc; then
                if [[ -f "$cert_path" && -f "$key_path" ]] && [[ -s "$cert_path" && -s "$key_path" ]]; then
                    echo "$domain" > /root/ca.log
                    # Remove old cron job if any, then add new one
                    sed -i '\!/root/\.acme\.sh/acme\.sh --cron!d' /etc/crontab >/dev/null 2>&1 
                    echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                    green "证书申请成功! 脚本申请到的证书 (cert.crt) 和私钥 (private.key) 文件已保存到 /root 文件夹下"
                    yellow "证书crt文件路径如下: $cert_path"
                    yellow "私钥key文件路径如下: $key_path"
                    hy_domain="$domain"
                else
                    red "错误：证书文件未成功生成或为空，请检查acme.sh的输出。"
                    exit 1
                fi
            else
                red "错误：acme.sh 证书安装步骤失败。请检查acme.sh的输出。"
                exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -p "请输入公钥文件 crt 的路径：" cert_path_input
        cert_path=$(realpath "$cert_path_input") # Get absolute path
        yellow "公钥文件 crt 的路径：$cert_path "
        read -p "请输入密钥文件 key 的路径：" key_path_input
        key_path=$(realpath "$key_path_input") # Get absolute path
        yellow "密钥文件 key 的路径：$key_path "

        if [[ ! -f "$cert_path" || ! -f "$key_path" ]]; then
            red "错误: 提供的证书或密钥文件路径无效。"
            exit 1
        fi
        
        read -p "请输入证书的域名 (用于SNI)：" domain_input # 这个domain将成为hy_domain (SNI)
        [[ -z "$domain_input" ]] && red "域名不能为空!" && exit 1
        domain="$domain_input" # for consistency if needed elsewhere
        hy_domain="$domain_input"
        yellow "证书SNI域名：$hy_domain"
        
        # 对于自定义证书，确保全局 $ip 已被 insthysteria 中的 realip 设置
        [[ -z "$ip" ]] && red "错误: 无法获取服务器IP以生成客户端配置。请检查realip函数或网络连接。" && exit 1

    else # 默认使用自签证书
        green "将使用必应自签证书作为 Hysteria 2 的节点证书"
        mkdir -p /etc/hysteria # Ensure directory exists
        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        openssl ecparam -genkey -name prime256v1 -out "$key_path"
        openssl req -new -x509 -days 36500 -key "$key_path" -out "$cert_path" -subj "/CN=www.bing.com"
        hy_domain="www.bing.com" # SNI
        domain="www.bing.com"    # 只是一个占位符域名
        
        # 对于自签证书，确保全局 $ip 已被 insthysteria 中的 realip 设置
        [[ -z "$ip" ]] && red "错误: 无法获取服务器IP以生成客户端配置。请检查realip函数或网络连接。" && exit 1
    fi
}

inst_port(){
    # Consider a more targeted removal if other rules exist for other services
    # For now, clearing only rules added by this script (if we can identify them, e.g., by comment)
    # Or, ask user if they want to clear all PREROUTING.
    # For simplicity now, let's assume this script manages its own rules.
    # If this function is re-run, it should ideally remove old rules first.
    # iptables -t nat -F PREROUTING >/dev/null 2>&1 # This is aggressive.

    read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
    [[ -z "$port" ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
            [[ -z "$port" ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    yellow "将在 Hysteria 2 节点使用的端口是：$port"
    inst_jump
}

inst_jump(){
    # Clear previous jump rules potentially added by this script
    # This requires a way to identify them, e.g., by a comment.
    # Example: iptables-save | grep "hysteria_jump_rule" | while read rule; do iptables -t nat -D $rule (pseudo-code)
    # For now, let user manage pre-existing rules or be aware of accumulation.

    green "Hysteria 2 端口使用模式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 单端口 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 端口跳跃"
    echo ""
    read -rp "请输入选项 [1-2]: " jumpInput
    if [[ $jumpInput == 2 ]]; then
        read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport_input
        read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport_input
        
        # Validate inputs
        if ! [[ "$firstport_input" =~ ^[0-9]+$ && "$firstport_input" -ge 1 && "$firstport_input" -le 65535 ]] || \
           ! [[ "$endport_input" =~ ^[0-9]+$ && "$endport_input" -ge 1 && "$endport_input" -le 65535 ]]; then
            red "错误：起始端口和末尾端口必须是1-65535之间的数字。"
            firstport="" endport="" # Clear to signify no jump
        elif [[ "$firstport_input" -ge "$endport_input" ]]; then
            red "错误：起始端口必须小于末尾端口。"
            firstport="" endport="" # Clear to signify no jump
        else
            firstport="$firstport_input" # Assign to global script variables if valid
            endport="$endport_input"
        fi
        
        if [[ -n "$firstport" && -n "$endport" ]]; then
            yellow "设置端口跳跃: $firstport:$endport -> $port"
            iptables -t nat -A PREROUTING -p udp --dport "$firstport:$endport" -j DNAT --to-destination ":$port" -m comment --comment "hysteria_jump_rule"
            ip6tables -t nat -A PREROUTING -p udp --dport "$firstport:$endport" -j DNAT --to-destination ":$port" -m comment --comment "hysteria_jump_rule"
            
            if command -v netfilter-persistent >/dev/null 2>&1; then
                netfilter-persistent save >/dev/null 2>&1
            elif command -v iptables-save >/dev/null 2>&1 && command -v ip6tables-save >/dev/null 2>&1; then
                 mkdir -p /etc/iptables
                 iptables-save > /etc/iptables/rules.v4
                 ip6tables-save > /etc/iptables/rules.v6
                 green "iptables规则已尝试保存到 /etc/iptables/"
            else
                yellow "警告: 未找到netfilter-persistent或iptables-save/ip6tables-save，防火墙规则可能在重启后丢失。"
            fi
        else
             red "端口跳跃设置无效或已跳过。"
             # Ensure these are unset if jump is not configured
             unset firstport
             unset endport
        fi
    else
        red "将继续使用单端口模式"
        unset firstport # Ensure these are unset if jump is not configured
        unset endport
    fi
}

inst_pwd(){
    read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" auth_pwd
    [[ -z "$auth_pwd" ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
}

inst_site(){
    read -rp "请输入 Hysteria 2 的伪装网站地址 （去除https://） [默认首尔大学]：" proxysite
    [[ -z "$proxysite" ]] && proxysite="en.snu.ac.kr"
    yellow "使用在 Hysteria 2 节点的伪装网站为：$proxysite"
}

insthysteria(){
    realip # Sets global $ip
    [[ -z "$ip" ]] && red "错误：无法获取服务器的公网IP地址！ Hysteria安装中止。" && exit 1
    yellow "脚本初步检测到服务器IP为: $ip (后续证书申请流程可能会根据DNS验证更新此IP)"


    if [[ ! ${SYSTEM} == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]} 
    fi
    ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps iptables-persistent netfilter-persistent dnsutils coreutils # coreutils for realpath

    if [[ ! -f "/usr/local/bin/hysteria" ]]; then
        wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
        if [[ ! -f "install_server.sh" ]]; then
            red "错误：无法下载 Hysteria 2 安装脚本 (install_server.sh)。"
            exit 1
        fi
        bash install_server.sh 
        rm -f install_server.sh
    else
        green "检测到 Hysteria 2 主程序已存在。"
    fi

    if [[ -f "/usr/local/bin/hysteria" ]]; then
        green "Hysteria 2 主程序准备就绪！"
    else
        red "Hysteria 2 主程序安装失败或未找到！请检查 install_server.sh 的输出。"
        exit 1
    fi

    # 询问用户 Hysteria 配置
    # inst_cert might update global $ip based on ACME validation
    inst_cert 
    # inst_port sets global $port and potentially $firstport, $endport
    inst_port 
    inst_pwd    # sets global $auth_pwd
    inst_site   # sets global $proxysite

    # $ip should now be the one validated by ACME, or the one from realip if not ACME
    [[ -z "$ip" ]] && red "内部错误: IP地址 ($ip) 未设置成功。安装中止。" && exit 1
    [[ -z "$port" ]] && red "内部错误: 端口 ($port) 未设置成功。安装中止。" && exit 1
    [[ -z "$auth_pwd" ]] && red "内部错误: 密码 ($auth_pwd) 未设置成功。安装中止。" && exit 1
    [[ -z "$hy_domain" ]] && red "内部错误: SNI域名 ($hy_domain) 未设置成功。安装中止。" && exit 1
    [[ -z "$cert_path" || -z "$key_path" ]] && red "内部错误: 证书路径未设置成功。安装中止。" && exit 1


    mkdir -p /etc/hysteria 
    cat << EOF > /etc/hysteria/config.yaml
listen: :$port

tls:
  cert: $cert_path
  key: $key_path

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

auth:
  type: password
  password: $auth_pwd

masquerade:
  type: proxy
  proxy:
    url: https://$proxysite
    rewriteHost: true
EOF

    local config_port_for_client="$port"
    if [[ -n "$firstport" && -n "$endport" && "$firstport" -lt "$endport" ]]; then 
        config_port_for_client="$port,$firstport-$endport"
    fi

    local config_ip_for_client="$ip"
    if [[ "$ip" == *":"* ]]; then # If $ip is IPv6, bracket it for client config
        config_ip_for_client="[$ip]"
    fi
    
    mkdir -p /root/hy 
    cat << EOF > /root/hy/hy-client.yaml
server: $config_ip_for_client:$config_port_for_client
auth: $auth_pwd
tls:
  sni: $hy_domain
  insecure: true 
quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432
fastOpen: true
socks5:
  listen: 127.0.0.1:5678
transport:
  udp:
    hopInterval: 30s
EOF
    cat << EOF > /root/hy/hy-client.json
{
  "server": "$config_ip_for_client:$config_port_for_client",
  "auth": "$auth_pwd",
  "tls": {
    "sni": "$hy_domain",
    "insecure": true
  },
  "quic": {
    "initStreamReceiveWindow": 16777216,
    "maxStreamReceiveWindow": 16777216,
    "initConnReceiveWindow": 33554432,
    "maxConnReceiveWindow": 33554432
  },
  "socks5": {
    "listen": "127.0.0.1:5678"
  },
  "transport": {
    "udp": {
      "hopInterval": "30s"
    }
  }
}
EOF

    local share_link_ip_formatted="$ip"
    if [[ "$ip" == *":"* ]]; then
        share_link_ip_formatted="[$ip]"
    fi
    local share_link_port_formatted="$port" # For base URL, use the main listening port
                                       # The full range will be in client config if jump is used
    
    # If port jump active, client needs full port string, some clients might parse it from server field.
    # For URL, some clients support "port,start-end", others only single port.
    # Standard URL format usually expects single port. We'll use the main listening port for simplicity.
    # The client config YAML/JSON will have the full port range if jump is active.
    # Consider if client expects `server_port` field for the range. Hysteria spec is `server: "host:port,start-end"`.
    
    url="hysteria2://$auth_pwd@$share_link_ip_formatted:$config_port_for_client/?insecure=1&sni=$hy_domain#Hysteria2-$(echo $SYS | awk '{print $1}')"
    echo "$url" > /root/hy/url.txt

    systemctl daemon-reload
    # install_server.sh should create hysteria-server.service or hysteria.service
    # Let's assume hysteria-server.service for now
    if systemctl list-unit-files | grep -qw hysteria-server.service; then
        SYSTEMD_SERVICE_NAME="hysteria-server.service"
    elif systemctl list-unit-files | grep -qw hysteria.service; then
        SYSTEMD_SERVICE_NAME="hysteria.service"
    else
        red "错误: 未找到Hysteria的systemd服务单元 (hysteria-server.service 或 hysteria.service)。"
        yellow "请检查 install_server.sh 的安装过程。"
        exit 1
    fi

    systemctl enable "$SYSTEMD_SERVICE_NAME"
    systemctl restart "$SYSTEMD_SERVICE_NAME"

    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 服务 ($SYSTEMD_SERVICE_NAME) 启动成功"
    else
        red "Hysteria 2 服务 ($SYSTEMD_SERVICE_NAME) 启动失败，请运行 'systemctl status $SYSTEMD_SERVICE_NAME' 查看服务状态并反馈"
        yellow "同时检查 'journalctl -u $SYSTEMD_SERVICE_NAME -n 50 --no-pager' 获取更多日志。"
        exit 1
    fi
    red "======================================================================================"
    green "Hysteria 2 代理服务安装完成"
    yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下，并保存到 /root/hy/hy-client.yaml"
    cat /root/hy/hy-client.yaml
    echo ""
    yellow "Hysteria 2 客户端 JSON 配置文件 hy-client.json 内容如下，并保存到 /root/hy/hy-client.json"
    cat /root/hy/hy-client.json
    echo ""
    yellow "Hysteria 2 节点分享链接如下，并保存到 /root/hy/url.txt"
    cat /root/hy/url.txt
    echo ""
    yellow "二维码分享链接 (内容同上):"
    qrencode -t ANSIUTF8 "$url"
    echo ""
    yellow "重要: 如果您使用了端口跳跃，请确保您的客户端支持该格式的服务端口定义 (port,start-end)。"
    yellow "       分享链接中的端口可能只显示主监听端口或完整范围，具体取决于客户端的解析能力。"
}

get_systemd_service_name(){
    if systemctl list-unit-files | grep -qw hysteria-server.service; then
        SYSTEMD_SERVICE_NAME="hysteria-server.service"
    elif systemctl list-unit-files | grep -qw hysteria.service; then
        SYSTEMD_SERVICE_NAME="hysteria.service"
    else
        SYSTEMD_SERVICE_NAME="" # Not found
    fi
}


unsthysteria(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then
        yellow "未检测到Hysteria服务单元，可能已卸载或安装不完整。"
    else
        systemctl stop "$SYSTEMD_SERVICE_NAME" >/dev/null 2>&1
        systemctl disable "$SYSTEMD_SERVICE_NAME" >/dev/null 2>&1
        rm -f "/lib/systemd/system/$SYSTEMD_SERVICE_NAME" "/usr/lib/systemd/system/$SYSTEMD_SERVICE_NAME"
        # Also remove potential template service if it was used by install_server.sh
        rm -f "/lib/systemd/system/${SYSTEMD_SERVICE_NAME//@/.service}" "/usr/lib/systemd/system/${SYSTEMD_SERVICE_NAME//@/.service}"
        rm -f "/lib/systemd/system/hysteria-server@.service" "/usr/lib/systemd/system/hysteria-server@.service" # common template name
        systemctl daemon-reload
    fi

    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy
    
    # Remove cron job for acme.sh if it was added by this script
    if grep -q "/root/.acme.sh/acme.sh --cron" /etc/crontab; then
        green "正在移除acme.sh的cron任务..."
        sed -i '\!/root/\.acme\.sh/acme\.sh --cron!d' /etc/crontab
    fi
    
    # Remove iptables rules added by this script (identified by comment)
    green "正在尝试移除由本脚本添加的iptables端口跳跃规则..."
    PORT_JUMP_COMMENT="hysteria_jump_rule"
    # IPv4 rules
    iptables-save | grep "$PORT_JUMP_COMMENT" | sed -e "s/^-A/D/" | while read -r rule_to_delete; do
        eval "iptables -t nat $rule_to_delete" # Use eval carefully or parse more strictly
    done
    # IPv6 rules
    ip6tables-save | grep "$PORT_JUMP_COMMENT" | sed -e "s/^-A/D/" | while read -r rule_to_delete; do
        eval "ip6tables -t nat $rule_to_delete" # Use eval carefully or parse more strictly
    done

    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1
    elif command -v iptables-save >/dev/null 2>&1 && command -v ip6tables-save >/dev/null 2>&1; then
         mkdir -p /etc/iptables
         iptables-save > /etc/iptables/rules.v4
         ip6tables-save > /etc/iptables/rules.v6
    fi
    
    read -rp "是否同时卸载acme.sh证书申请工具 (相关证书可能丢失)？[y/N]: " remove_acme
    if [[ "$remove_acme" =~ ^[Yy]$ ]]; then
        if command -v ~/.acme.sh/acme.sh &>/dev/null; then
            ~/.acme.sh/acme.sh --uninstall
            rm -rf /root/.acme.sh
            green "acme.sh已卸载。"
        else
            yellow "未找到acme.sh，可能已卸载或未安装。"
        fi
    fi

    green "Hysteria 2 已尝试彻底卸载完成！"
}

starthysteria(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务未找到!" && return; fi
    systemctl start "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 服务已启动。"
    else
        red "Hysteria 2 服务启动失败。"
        yellow "请运行 'systemctl status $SYSTEMD_SERVICE_NAME' 和 'journalctl -u $SYSTEMD_SERVICE_NAME -n 50 --no-pager' 查看日志。"
    fi
}

stophysteria(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务未找到!" && return; fi
    systemctl stop "$SYSTEMD_SERVICE_NAME"
    green "Hysteria 2 服务已停止。"
}

hysteriaswitch(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" && "$1" != "menu" ]]; then # If called not from menu return, and service not found
        red "Hysteria 服务未安装或无法确定服务名。"
        read -n 1 -s -r -p "按任意键返回主菜单..."
        menu
        return
    fi

    yellow "请选择你需要的操作 (服务: ${SYSTEMD_SERVICE_NAME:-未找到}):"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"
    echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"
    echo -e " ${GREEN}4.${PLAIN} 查看 Hysteria 2 状态"
    echo -e " ${GREEN}5.${PLAIN} 查看 Hysteria 2 日志 (最近50条)"
    echo -e " ${GREEN}0.${PLAIN} 返回主菜单"
    echo ""
    read -rp "请输入选项 [0-5]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) if [[ -n "$SYSTEMD_SERVICE_NAME" ]]; then systemctl restart "$SYSTEMD_SERVICE_NAME"; green "Hysteria 2 服务已尝试重启。"; else red "服务名未知，无法重启。"; fi ;;
        4 ) if [[ -n "$SYSTEMD_SERVICE_NAME" ]]; then systemctl status "$SYSTEMD_SERVICE_NAME"; else red "服务名未知，无法查看状态。"; fi ;;
        5 ) if [[ -n "$SYSTEMD_SERVICE_NAME" ]]; then journalctl -u "$SYSTEMD_SERVICE_NAME" -n 50 --no-pager; else red "服务名未知，无法查看日志。"; fi ;;
        0 ) menu ;;
        * ) red "无效输入!" ; sleep 1 ;;
    esac
    echo ""
    read -n 1 -s -r -p "按任意键返回操作菜单..."
    hysteriaswitch "menu" # Pass arg to avoid re-check for service name if returning
}

changeport(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装，无法修改配置。" && return; fi
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知!" && return; fi
    
    local old_server_port=$(grep -oP 'listen: : *\K[0-9]+' /etc/hysteria/config.yaml 2>/dev/null)
    if [[ -z "$old_server_port" ]]; then
        red "错误：无法从配置文件中读取旧的监听端口。"
        return 1
    fi
    
    read -p "当前监听端口: $old_server_port. 设置新的 Hysteria 2 监听端口[1-65535]（回车则随机分配端口）：" new_port
    [[ -z "$new_port" ]] && new_port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$new_port") || "$new_port" == "$old_server_port" ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$new_port") ]]; then
            echo -e "${RED} $new_port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 2 监听端口 [1-65535]（回车则随机分配端口）：" new_port
            [[ -z "$new_port" ]] && new_port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    sed -i "s/listen: :$old_server_port/listen: :$new_port/g" /etc/hysteria/config.yaml
    
    # Update client configs and share URL
    # This is complex if port jump is involved. For now, assumes $ip and $hy_domain are current.
    # The $ip variable should be the one hysteria is reachable on (from realip or ACME validation)
    # Re-fetch $ip if necessary, or assume it's correctly set from install/last realip call.
    # If 'ip' is not defined globally or from a previous step, we need it for client configs.
    if [[ -z "$ip" ]]; then realip; fi 
    [[ -z "$ip" ]] && red "无法获取服务器IP更新客户端配置。" && return 1
    
    local client_ip_formatted="$ip"
    if [[ "$ip" == *":"* ]]; then client_ip_formatted="[$ip]"; fi

    local old_client_config_port_part # This needs to find "ip:port" or "ip:port,start-end"
    # Simplistic replacement for main port; jump range needs careful handling if it's changed.
    # Assuming old_server_port is the primary port in client configs.
    sed -i "s/$client_ip_formatted:$old_server_port/$client_ip_formatted:$new_port/1" /root/hy/hy-client.yaml # Replace first instance
    sed -i "s/\"server\": \"$client_ip_formatted:$old_server_port\"/\"server\": \"$client_ip_formatted:$new_port\"/1" /root/hy/hy-client.json

    # URL update (only the main port part)
    sed -i "s/@$client_ip_formatted:$old_server_port/@$client_ip_formatted:$new_port/" /root/hy/url.txt
    
    # Note: If port jump was used, and $old_server_port was part of the DNAT rule's --to-destination,
    # the iptables rules for port jump also need to be updated to DNAT to $new_port.
    # This is an advanced case not fully handled here for simplicity.

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 监听端口已成功修改为：$new_port"
        yellow "客户端配置文件中的主要端口也已尝试更新。"
        yellow "如果使用了端口跳跃，旧的跳跃规则仍指向旧的主端口 $old_server_port。您可能需要手动更新防火墙规则或重新设置端口跳跃。"
        showconf
    else
        red "Hysteria 2 服务重启失败，端口更改可能未生效。请检查日志。"
    fi
}

changepasswd(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装，无法修改配置。" && return; fi
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知!" && return; fi

    local oldpasswd=$(grep -oP 'password: \K\S+' /etc/hysteria/config.yaml 2>/dev/null)
    if [[ -z "$oldpasswd" ]]; then
        red "错误：无法从配置文件中读取旧密码。"
        return 1
    fi

    read -p "当前密码: $oldpasswd. 设置新的 Hysteria 2 密码（回车跳过为随机字符）：" new_passwd
    [[ -z "$new_passwd" ]] && new_passwd=$(date +%s%N | md5sum | cut -c 1-8)

    sed -i "s/password: $oldpasswd/password: $new_passwd/g" /etc/hysteria/config.yaml
    sed -i "s/auth: $oldpasswd/auth: $new_passwd/g" /root/hy/hy-client.yaml
    sed -i "s/\"auth\": \"$oldpasswd\"/\"auth\": \"$new_passwd\"/g" /root/hy/hy-client.json

    local old_url_auth_part="hysteria2://$oldpasswd@"
    local new_url_auth_part="hysteria2://$new_passwd@"
    # Need to escape @ for sed if it's the delimiter
    sed -i "s#${old_url_auth_part}#${new_url_auth_part}#g" /root/hy/url.txt

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 节点密码已成功修改为：$new_passwd"
        yellow "客户端配置文件和分享链接中的密码已更新。"
        showconf
    else
        red "Hysteria 2 服务重启失败，密码更改可能未生效。请检查日志。"
    fi
}

change_cert(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装，无法修改配置。" && return; fi
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知!" && return; fi

    local old_cert_path_cfg=$(grep -oP 'cert: \K\S+' /etc/hysteria/config.yaml)
    local old_key_path_cfg=$(grep -oP 'key: \K\S+' /etc/hysteria/config.yaml)
    local old_hy_domain_client=$(grep -oP 'sni: \K\S+' /root/hy/hy-client.yaml)

    # Preserve current global $ip before inst_cert potentially changes it (if ACME is chosen)
    local preserved_ip_before_cert_change="$ip"
    
    # inst_cert will guide through new certificate selection/generation.
    # It will set global $cert_path, $key_path, $hy_domain, and potentially update global $ip if ACME is used.
    inst_cert 

    # After inst_cert, $cert_path, $key_path, $hy_domain, and $ip (if ACME) are updated.
    # Now update the server config and client configs with these new values.

    sed -i "s|cert: $old_cert_path_cfg|cert: $cert_path|g" /etc/hysteria/config.yaml
    sed -i "s|key: $old_key_path_cfg|key: $key_path|g" /etc/hysteria/config.yaml
    
    sed -i "s/sni: $old_hy_domain_client/sni: $hy_domain/g" /root/hy/hy-client.yaml
    sed -i "s/\"sni\": \"$old_hy_domain_client\"/\"sni\": \"$hy_domain\"/g" /root/hy/hy-client.json
    
    # Update SNI in URL
    # Need to escape special characters in $old_hy_domain_client and $hy_domain for sed if they contain them
    local escaped_old_sni=$(printf '%s\n' "$old_hy_domain_client" | sed 's:[][\/.^$*]:\\&:g')
    local escaped_new_sni=$(printf '%s\n' "$hy_domain" | sed 's:[][\/.^$*]:\\&:g')
    sed -i "s/sni=$escaped_old_sni/sni=$escaped_new_sni/g" /root/hy/url.txt

    # If $ip was changed by ACME in inst_cert, client server IP also needs update.
    # The global $ip is now the new one if ACME was run.
    if [[ "$ip" != "$preserved_ip_before_cert_change" ]]; then
        yellow "服务器IP因ACME验证已更新为: $ip。正在更新客户端配置中的服务器地址..."
        local old_client_ip_formatted="$preserved_ip_before_cert_change"
        if [[ "$preserved_ip_before_cert_change" == *":"* ]]; then old_client_ip_formatted="[$preserved_ip_before_cert_change]"; fi
        
        local new_client_ip_formatted="$ip"
        if [[ "$ip" == *":"* ]]; then new_client_ip_formatted="[$ip]"; fi

        sed -i "s/server: $old_client_ip_formatted:/server: $new_client_ip_formatted:/g" /root/hy/hy-client.yaml
        sed -i "s/\"server\": \"$old_client_ip_formatted:/\"server\": \"$new_client_ip_formatted:/g" /root/hy/hy-client.json
        # URL server IP part update (more complex due to @ and potential brackets)
        # This simplistic replacement might fail if domain name resembles an IP. A more robust regex needed.
        # For now, assuming $preserved_ip_before_cert_change is unique enough in the URL string.
        sed -i "s/@$old_client_ip_formatted/@$new_client_ip_formatted/g" /root/hy/url.txt # Basic for non-bracketed IPv4
        sed -i "s/@\[$preserved_ip_before_cert_change\]/@\[$new_client_ip_formatted\]/g" /root/hy/url.txt # For bracketed IPv6
    fi

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 节点证书信息已成功修改。"
        yellow "客户端配置文件和分享链接中的SNI及服务器IP (如果因ACME变更) 已更新。"
        showconf
    else
        red "Hysteria 2 服务重启失败，证书更改可能未生效。请检查日志。"
    fi
}

changeproxysite(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装，无法修改配置。" && return; fi
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知!" && return; fi

    local oldproxysite=$(grep -oP 'url: https://\K\S+' /etc/hysteria/config.yaml)
    if [[ -z "$oldproxysite" ]]; then
        red "错误：无法从配置文件中读取旧的伪装网站。"
        return 1
    fi
    
    inst_site # This function sets global $proxysite

    # Escape for sed
    local escaped_oldproxysite=$(printf '%s\n' "$oldproxysite" | sed 's:[][\/.^$*]:\\&:g')
    local escaped_newproxysite=$(printf '%s\n' "$proxysite" | sed 's:[][\/.^$*]:\\&:g')

    sed -i "s|url: https://$escaped_oldproxysite|url: https://$escaped_newproxysite|g" /etc/hysteria/config.yaml

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 节点伪装网站已成功修改为：$proxysite"
    else
        red "Hysteria 2 服务重启失败，伪装网站更改可能未生效。请检查日志。"
    fi
}

changeconf(){
    if [[ ! -f "/etc/hysteria/config.yaml" ]]; then
        red "Hysteria 2 未安装，无法修改配置。"
        read -n 1 -s -r -p "按任意键返回主菜单..."
        menu
        return
    fi
    green "Hysteria 2 配置变更选择如下:"
    echo -e " ${GREEN}1.${PLAIN} 修改监听端口"
    echo -e " ${GREEN}2.${PLAIN} 修改连接密码"
    echo -e " ${GREEN}3.${PLAIN} 修改证书 (类型/路径/SNI)"
    echo -e " ${GREEN}4.${PLAIN} 修改伪装网站"
    echo -e " ${GREEN}0.${PLAIN} 返回主菜单"
    echo ""
    read -p " 请选择操作 [0-4]：" confAnswer
    case $confAnswer in
        1 ) changeport ;;
        2 ) changepasswd ;;
        3 ) change_cert ;;
        4 ) changeproxysite ;;
        0 ) menu ;;
        * ) red "无效输入!"; sleep 1 ;;
    esac
    echo ""
    read -n 1 -s -r -p "按任意键返回配置修改菜单..."
    changeconf
}

showconf(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then
        red "Hysteria 2 尚未安装或配置文件不存在。"
        return
    fi
    # Ensure $ip is current for display, though client files hold their configured values
    # local display_ip_current=""
    # if command -v realip &>/dev/null ; then realip; display_ip_current="$ip"; else display_ip_current="N/A"; fi
    # if [[ "$display_ip_current" == *":"* ]]; then display_ip_current="[$display_ip_current]"; fi
    # yellow "当前服务器检测到的IP: $display_ip_current (客户端配置可能使用安装时的IP)"
    
    get_systemd_service_name
    green "--- Hysteria 2 服务器配置 (/etc/hysteria/config.yaml) (服务: ${SYSTEMD_SERVICE_NAME:-未知}) ---"
    cat /etc/hysteria/config.yaml
    green "--------------------------------------------------------------------"
    echo ""
    yellow "Hysteria 2 客户端 YAML 配置文件 (/root/hy/hy-client.yaml):"
    cat /root/hy/hy-client.yaml
    echo ""
    yellow "Hysteria 2 客户端 JSON 配置文件 (/root/hy/hy-client.json):"
    cat /root/hy/hy-client.json
    echo ""
    yellow "Hysteria 2 节点分享链接 (/root/hy/url.txt):"
    local current_url=$(cat /root/hy/url.txt)
    echo "$current_url"
    echo ""
    yellow "二维码分享链接 (内容同上):"
    qrencode -t ANSIUTF8 "$current_url"
}

menu() {
    clear
    echo "#############################################################"
    echo -e "#         ${GREEN}Hysteria 2 一键安装脚本 (增强版)${PLAIN}         #"
    echo -e "#       ${YELLOW}作者: Misaka, Google Gemini (改进版)${PLAIN}         #"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} ${GREEN}安装 Hysteria 2${PLAIN}"
    echo -e " ${RED}2.${PLAIN} ${RED}卸载 Hysteria 2${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " ${GREEN}3.${PLAIN} Hysteria 2 服务管理 (启/停/重启/状态/日志)"
    echo -e " ${GREEN}4.${PLAIN} 修改 Hysteria 2 配置 (端/密/证/伪)"
    echo -e " ${GREEN}5.${PLAIN} 显示 Hysteria 2 配置文件和分享链接"
    echo " ------------------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 退出脚本"
    echo ""
    
    get_systemd_service_name
    if [[ -f "/etc/hysteria/config.yaml" && -n "$SYSTEMD_SERVICE_NAME" ]]; then
        local current_status=$(systemctl is-active "$SYSTEMD_SERVICE_NAME")
        if [[ "$current_status" == "active" ]]; then
             green "Hysteria 2 当前状态: $current_status (运行中)"
        else
             yellow "Hysteria 2 当前状态: $current_status"
        fi
        local current_port=$(grep -oP 'listen: : *\K[0-9]+' /etc/hysteria/config.yaml 2>/dev/null)
        local current_sni=$(grep -oP 'sni: \K\S+' /root/hy/hy-client.yaml 2>/dev/null || echo "N/A")
        yellow "监听端口: ${current_port:-N/A}, SNI: ${current_sni:-N/A}"
    elif [[ -f "/etc/hysteria/config.yaml" ]]; then
        yellow "Hysteria 2 配置文件存在，但服务单元名无法确定。"
    else
        yellow "Hysteria 2 似乎未安装。"
    fi
    echo ""
    read -rp "请输入选项 [0-5]: " menuInput
    case $menuInput in
        1 ) insthysteria ;;
        2 ) unsthysteria ;;
        3 ) hysteriaswitch ;;
        4 ) changeconf ;;
        5 ) showconf ;;
        0 ) exit 0 ;;
        * ) red "无效输入!" && sleep 1 ;;
    esac
    # Add a slight pause before re-looping to menu if not exiting
    if [[ "$menuInput" != "0" ]]; then
        echo ""
        read -n 1 -s -r -p "按任意键返回主菜单..."
    fi
    menu 
}

# --- Global variable declarations ---
# These will be set by various functions.
ip="" # Server IP, set by realip initially, potentially updated by inst_cert ACME
cert_path=""
key_path=""
hy_domain="" # SNI domain
domain=""    # General domain variable, often same as hy_domain
port=""      # Main listening port
firstport="" # Port jump start
endport=""   # Port jump end
auth_pwd=""
proxysite=""
SYSTEMD_SERVICE_NAME="" # Determined by get_systemd_service_name

# --- Main execution ---
menu
