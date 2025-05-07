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

realip(){
    # Prefer IPv4, fallback to IPv6
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
        else
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                realip
                wg-quick up wgcf >/dev/null 2>&1
                systemctl start warp-go >/dev/null 2>&1
            else
                realip
            fi
            
            [[ -z "$ip" ]] && red "错误：无法获取服务器的公网IP地址！" && exit 1
            yellow "服务器将用于证书申请的IP地址: $ip"

            read -p "请输入需要申请证书的域名：" domain
            [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
            green "已输入的域名：$domain" && sleep 1

            local is_server_ip_ipv6=false
            if [[ "$ip" == *":"* ]]; then # Check if $ip contains a colon, indicating IPv6
                is_server_ip_ipv6=true
            fi

            local resolved_domain_ip=""
            local dns_query_type=""

            if $is_server_ip_ipv6; then
                dns_query_type="AAAA"
                resolved_domain_ip=$(dig AAAA +short "$domain" | head -n1)
                green "正在检查域名 '$domain' 的 AAAA 记录..."
            else
                dns_query_type="A"
                resolved_domain_ip=$(dig A +short "$domain" | head -n1)
                green "正在检查域名 '$domain' 的 A 记录..."
            fi

            if [[ -z "$resolved_domain_ip" ]]; then
                red "错误：无法通过 '$dns_query_type' 记录解析域名 '$domain'。"
                yellow "请检查您的DNS设置和域名是否正确，并等待DNS传播。"
                exit 1
            fi
            
            if [[ "$resolved_domain_ip" == "$ip" ]]; then
                green "域名 '$domain' ($dns_query_type 记录: $resolved_domain_ip) 与服务器IP '$ip' 匹配成功。"
                
                # Install necessary packages for acme.sh
                ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl
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
                curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
                source ~/.bashrc # Reload bashrc to ensure acme.sh command is available
                ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

                # Issue certificate
                local acme_cmd_base="~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --insecure"
                if $is_server_ip_ipv6; then # If server IP is IPv6, acme.sh should listen on IPv6
                    bash $acme_cmd_base --listen-v6
                else # Otherwise, acme.sh listens on IPv4 (default)
                    bash $acme_cmd_base
                fi
                
                # Install certificate
                if ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/private.key --fullchain-file /root/cert.crt --ecc; then
                    if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]]; then
                        echo $domain > /root/ca.log
                        sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1 # Remove old cron job if any
                        echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                        green "证书申请成功! 脚本申请到的证书 (cert.crt) 和私钥 (private.key) 文件已保存到 /root 文件夹下"
                        yellow "证书crt文件路径如下: /root/cert.crt"
                        yellow "私钥key文件路径如下: /root/private.key"
                        hy_domain=$domain
                    else
                        red "错误：证书文件未成功生成或为空，请检查acme.sh的输出。"
                        exit 1
                    fi
                else
                    red "错误：acme.sh 证书安装步骤失败。"
                    exit 1
                fi
            else
                red "错误：域名 '$domain' 解析的IP ($dns_query_type 记录: $resolved_domain_ip) 与当前服务器IP ($ip) 不匹配。"
                green "建议如下："
                yellow "1. 请确保CloudFlare小云朵为关闭状态(仅限DNS), 其他域名解析或CDN网站设置同理。"
                yellow "2. 请检查DNS解析设置，确保 '$domain' 的 '$dns_query_type' 记录指向 '$ip'。"
                yellow "3. 如果您的服务器同时具有IPv4和IPv6地址，请确保您为 '$domain' 设置了正确的DNS记录类型 ($dns_query_type) 并指向相应的服务器IP。"
                yellow "   - 服务器的真实IP (脚本检测到的用于验证的IP): $ip"
                yellow "   - 域名 '$domain' 解析到的 ($dns_query_type) IP: $resolved_domain_ip"
                # Attempt to show the other IP type for more context if available
                if $is_server_ip_ipv6; then # If we were checking AAAA, also show A if it exists
                    local other_type_ip=$(dig A +short "$domain" | head -n1)
                    if [[ -n "$other_type_ip" ]]; then
                        yellow "   - 域名 '$domain' 解析到的 (A) IP: $other_type_ip (供参考)"
                    fi
                else # If we were checking A, also show AAAA if it exists
                    local other_type_ip=$(dig AAAA +short "$domain" | head -n1)
                    if [[ -n "$other_type_ip" ]]; then
                        yellow "   - 域名 '$domain' 解析到的 (AAAA) IP: $other_type_ip (供参考)"
                    fi
                fi
                exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -p "请输入公钥文件 crt 的路径：" cert_path
        yellow "公钥文件 crt 的路径：$cert_path "
        read -p "请输入密钥文件 key 的路径：" key_path
        yellow "密钥文件 key 的路径：$key_path "
        read -p "请输入证书的域名：" domain
        yellow "证书域名：$domain"
        hy_domain=$domain
    else
        green "将使用必应自签证书作为 Hysteria 2 的节点证书"
        mkdir -p /etc/hysteria # Ensure directory exists
        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
        openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=www.bing.com"
        # No need for chmod 777, hysteria runs as root or has appropriate capabilities
        hy_domain="www.bing.com"
        domain="www.bing.com"
    fi
}

inst_port(){
    iptables -t nat -F PREROUTING >/dev/null 2>&1 # This clears ALL PREROUTING rules, might be too aggressive
    # Consider a more targeted removal if other rules exist for other services

    read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    yellow "将在 Hysteria 2 节点使用的端口是：$port"
    inst_jump
}

inst_jump(){
    green "Hysteria 2 端口使用模式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 单端口 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 端口跳跃"
    echo ""
    read -rp "请输入选项 [1-2]: " jumpInput
    if [[ $jumpInput == 2 ]]; then
        read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
        read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
        if [[ -z "$firstport" || -z "$endport" ]] || ! [[ "$firstport" =~ ^[0-9]+$ && "$endport" =~ ^[0-9]+$ ]]; then
            red "错误：起始端口和末尾端口必须是数字。"
            exit 1
        fi
        if [[ $firstport -ge $endport ]]; then
            until [[ $firstport -lt $endport ]]; do # Corrected logic to ensure firstport < endport
                red "你设置的起始端口必须小于末尾端口，请重新输入起始和末尾端口"
                read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
                read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
                if [[ -z "$firstport" || -z "$endport" ]] || ! [[ "$firstport" =~ ^[0-9]+$ && "$endport" =~ ^[0-9]+$ ]]; then
                     red "错误：起始端口和末尾端口必须是数字。跳过端口跳跃设置。"
                     firstport="" # Reset to avoid applying bad rules
                     endport=""
                     break
                fi
            done
        fi
        
        if [[ -n "$firstport" && -n "$endport" && "$firstport" -lt "$endport" ]]; then
            yellow "设置端口跳跃: $firstport:$endport -> $port"
            iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
            ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
            # Save rules. Ensure netfilter-persistent is properly configured.
            if command -v netfilter-persistent >/dev/null 2>&1; then
                netfilter-persistent save >/dev/null 2>&1
            elif command -v iptables-save >/dev/null 2>&1; then # Fallback for systems without netfilter-persistent
                 iptables-save > /etc/iptables/rules.v4
                 ip6tables-save > /etc/iptables/rules.v6
            fi
        else
             red "端口跳跃设置无效或已跳过。"
        fi
    else
        red "将继续使用单端口模式"
    fi
}

inst_pwd(){
    read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
}

inst_site(){
    read -rp "请输入 Hysteria 2 的伪装网站地址 （去除https://） [默认首尔大学]：" proxysite
    [[ -z $proxysite ]] && proxysite="en.snu.ac.kr"
    yellow "使用在 Hysteria 2 节点的伪装网站为：$proxysite"
}

insthysteria(){
    warpv6=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    warpv4=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ $warpv4 =~ on|plus || $warpv6 =~ on|plus ]]; then
        wg-quick down wgcf >/dev/null 2>&1
        systemctl stop warp-go >/dev/null 2>&1
        realip # Ensure realip is called to get the non-WARP IP
        systemctl start warp-go >/dev/null 2>&1 # Restart warp if it was on
        wg-quick up wgcf >/dev/null 2>&1
    else
        realip
    fi
    
    [[ -z "$ip" ]] && red "错误：无法获取服务器的公网IP地址！ Hysteria安装中止。" && exit 1

    if [[ ! ${SYSTEM} == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]} # Corrected to use array index
    fi
    # Ensure procps (for ss) and iptables-persistent/netfilter-persistent are installed
    ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps iptables-persistent netfilter-persistent dig # Added dig

    # Check if hysteria binary already exists from a previous attempt or manual install
    if [[ ! -f "/usr/local/bin/hysteria" ]]; then
        # Download and install hysteria server script
        wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
        if [[ ! -f "install_server.sh" ]]; then
            red "错误：无法下载 Hysteria 2 安装脚本 (install_server.sh)。"
            exit 1
        fi
        bash install_server.sh # This script should install hysteria to /usr/local/bin/hysteria
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
    inst_cert
    inst_port
    inst_pwd
    inst_site

    mkdir -p /etc/hysteria # Ensure directory exists
    # 设置 Hysteria 配置文件
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

    # 确定最终入站端口范围
    if [[ -n $firstport && -n $endport && "$firstport" -lt "$endport" ]]; then # Added check for valid port range
        last_port="$port,$firstport-$endport"
    else
        last_port=$port
    fi

    # 给 IPv6 地址加中括号
    local last_ip_for_config="$ip" # Use the $ip variable determined by realip
    if [[ "$ip" == *":"* ]]; then
        last_ip_for_config="[$ip]"
    fi
    
    # Use the original $ip for share link, clients usually handle bare IPv6 too
    # but for config SNI and server address, brackets are safer for IPv6.
    # The $hy_domain is critical for SNI.

    mkdir -p /root/hy # Ensure directory exists
    cat << EOF > /root/hy/hy-client.yaml
server: $last_ip_for_config:$last_port
auth: $auth_pwd
tls:
  sni: $hy_domain
  insecure: true # Assuming self-signed or ACME with LE, often clients need this for custom CAs
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
  "server": "$last_ip_for_config:$last_port",
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

    # For share link, use $ip directly. If it's IPv6, it should be bracketed for URLs.
    local share_link_ip="$ip"
    if [[ "$ip" == *":"* ]]; then
        share_link_ip="[$ip]"
    fi
    url="hysteria2://$auth_pwd@$share_link_ip:$last_port/?insecure=1&sni=$hy_domain#Hysteria2-misaka"
    echo $url > /root/hy/url.txt

    systemctl daemon-reload
    systemctl enable hysteria-server.service # Assuming install_server.sh creates this service name
    systemctl restart hysteria-server.service # Use restart to ensure it picks up new config

    if [[ -n $(systemctl status hysteria-server.service 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 服务启动成功"
    else
        red "Hysteria 2 服务启动失败，请运行 systemctl status hysteria-server.service 查看服务状态并反馈，脚本退出"
        yellow "同时检查 journalctl -u hysteria-server.service -n 50 --no-pager 获取更多日志。"
        exit 1
    fi
    red "======================================================================================"
    green "Hysteria 2 代理服务安装完成"
    yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下，并保存到 /root/hy/hy-client.yaml"
    red "$(cat /root/hy/hy-client.yaml)"
    yellow "Hysteria 2 客户端 JSON 配置文件 hy-client.json 内容如下，并保存到 /root/hy/hy-client.json"
    red "$(cat /root/hy/hy-client.json)"
    yellow "Hysteria 2 节点分享链接如下，并保存到 /root/hy/url.txt"
    red "$(cat /root/hy/url.txt)"
    yellow "二维码分享链接 (内容同上):"
    qrencode -t ANSIUTF8 "$url"
}

unsthysteria(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1
    rm -f /lib/systemd/system/hysteria-server.service /usr/lib/systemd/system/hysteria-server.service # Check common paths
    rm -f /lib/systemd/system/hysteria-server@.service /usr/lib/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy
    # Remove cron job for acme.sh if it was added by this script
    if grep -q "/root/.acme.sh/acme.sh --cron" /etc/crontab; then
        green "正在移除acme.sh的cron任务..."
        sed -i '\!/root/\.acme\.sh/acme\.sh --cron!d' /etc/crontab
    fi
    # Consider removing iptables rules more selectively if this script added them with a comment
    # For now, clearing all PREROUTING as before, user discretion advised if other services use it.
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    ip6tables -t nat -F PREROUTING >/dev/null 2>&1
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1
        netfilter-persistent flush >/dev/null 2>&1 # flush might be needed too
    elif command -v iptables-save >/dev/null 2>&1; then
         iptables-save > /etc/iptables/rules.v4 # This saves current (empty PREROUTING) state
         ip6tables-save > /etc/iptables/rules.v6
    fi
    # Optionally remove acme.sh directory
    read -rp "是否同时卸载acme.sh证书申请工具 (相关证书可能丢失)？[y/N]: " remove_acme
    if [[ "$remove_acme" =~ ^[Yy]$ ]]; then
        ~/.acme.sh/acme.sh --uninstall
        rm -rf /root/.acme.sh
        green "acme.sh已卸载。"
    fi

    green "Hysteria 2 已彻底卸载完成！"
}

starthysteria(){
    systemctl start hysteria-server.service
    # Enable is usually good practice to ensure it starts on boot
    # systemctl enable hysteria-server.service >/dev/null 2>&1
    if [[ -n $(systemctl status hysteria-server.service 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 服务已启动。"
    else
        red "Hysteria 2 服务启动失败。"
        yellow "请运行 'systemctl status hysteria-server.service' 和 'journalctl -u hysteria-server.service -n 50 --no-pager' 查看日志。"
    fi
}

stophysteria(){
    systemctl stop hysteria-server.service
    # systemctl disable hysteria-server.service >/dev/null 2>&1 # Disabling on stop might be too much, usually handled by uninstall
    green "Hysteria 2 服务已停止。"
}

hysteriaswitch(){
    yellow "请选择你需要的操作："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"
    echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"
    echo -e " ${GREEN}4.${PLAIN} 查看 Hysteria 2 状态"
    echo -e " ${GREEN}5.${PLAIN} 查看 Hysteria 2 日志"
    echo ""
    read -rp "请输入选项 [1-5] (其他输入则返回主菜单): " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) systemctl restart hysteria-server.service; green "Hysteria 2 服务已尝试重启。" ;;
        4 ) systemctl status hysteria-server.service ;;
        5 ) journalctl -u hysteria-server.service -n 50 --no-pager ;;
        * ) menu ;;
    esac
    echo ""
    read -n 1 -s -r -p "按任意键返回操作菜单..."
    hysteriaswitch # Return to this submenu
}

changeport(){
    local oldport=$(grep -oP 'listen: : *\K[0-9]+' /etc/hysteria/config.yaml 2>/dev/null)
    if [[ -z "$oldport" ]]; then
        red "错误：无法从配置文件中读取旧端口。"
        return 1
    fi
    
    read -p "当前端口: $oldport. 设置新的 Hysteria 2 端口[1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    sed -i "s/listen: :$oldport/listen: :$port/g" /etc/hysteria/config.yaml
    # Update client configs and share URL (assuming $ip and $hy_domain are still relevant or re-fetched)
    # For simplicity, this part needs careful handling of how $last_port is constructed if port jumping was used.
    # Assuming single port for now in client config updates.
    # This part is tricky because the original 'last_port' could be a range.
    # We should re-evaluate if it was a range or single.
    local old_client_server_line=$(grep "server:" /root/hy/hy-client.yaml | awk '{print $2}')
    local new_client_server_line=$(echo "$old_client_server_line" | sed "s/:$oldport/:$port/") # Basic replacement
    # This needs to be more robust if port jumping is active, as $oldport might be part of firstport-endport too.
    # A simpler approach: re-generate client files or guide user.
    
    # For now, only update the main listening port in client files for basic cases.
    # If port jump is active, this won't update the jump range in client files.
    sed -i "s/$oldport/$port/g" /root/hy/hy-client.yaml # This might be too broad, be careful.
    sed -i "s/$oldport/$port/g" /root/hy/hy-client.json # Same here.
    local old_url_port_part="@$ip:$oldport"
    if [[ "$ip" == *":"* ]]; then
        old_url_port_part="@\[$ip\]:$oldport" # if $ip was IPv6
    fi
    local new_url_port_part="@$ip:$port"
    if [[ "$ip" == *":"* ]]; then
        new_url_port_part="@\[$ip\]:$port"
    fi
    sed -i "s/$old_url_port_part/$new_url_port_part/g" /root/hy/url.txt


    systemctl restart hysteria-server.service
    if [[ -n $(systemctl status hysteria-server.service 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 端口已成功修改为：$port"
        yellow "客户端配置文件中的端口也已尝试更新。如果使用了端口跳跃，请仔细检查或手动更新。"
        showconf
    else
        red "Hysteria 2 服务重启失败，端口更改可能未生效。请检查日志。"
    fi
}

changepasswd(){
    local oldpasswd=$(grep -oP 'password: \K\S+' /etc/hysteria/config.yaml 2>/dev/null)
    if [[ -z "$oldpasswd" ]]; then
        red "错误：无法从配置文件中读取旧密码。"
        return 1
    fi

    read -p "当前密码: $oldpasswd. 设置新的 Hysteria 2 密码（回车跳过为随机字符）：" passwd
    [[ -z $passwd ]] && passwd=$(date +%s%N | md5sum | cut -c 1-8)

    sed -i "s/password: $oldpasswd/password: $passwd/g" /etc/hysteria/config.yaml
    sed -i "s/auth: $oldpasswd/auth: $passwd/g" /root/hy/hy-client.yaml
    sed -i "s/\"auth\": \"$oldpasswd\"/\"auth\": \"$passwd\"/g" /root/hy/hy-client.json

    # Update URL
    local old_url_auth_part="hysteria2://$oldpasswd@"
    local new_url_auth_part="hysteria2://$passwd@"
    sed -i "s|$old_url_auth_part|$new_url_auth_part|g" /root/hy/url.txt


    systemctl restart hysteria-server.service
    if [[ -n $(systemctl status hysteria-server.service 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 节点密码已成功修改为：$passwd"
        yellow "客户端配置文件和分享链接中的密码已更新。"
        showconf
    else
        red "Hysteria 2 服务重启失败，密码更改可能未生效。请检查日志。"
    fi
}

change_cert(){
    local old_cert=$(grep -oP 'cert: \K\S+' /etc/hysteria/config.yaml)
    local old_key=$(grep -oP 'key: \K\S+' /etc/hysteria/config.yaml)
    local old_hydomain=$(grep -oP 'sni: \K\S+' /root/hy/hy-client.yaml)

    # Call inst_cert to guide through new certificate selection/generation
    # inst_cert will set $cert_path, $key_path, $hy_domain globally if user completes it
    # We need to preserve them or pass them back carefully.
    # For now, inst_cert updates these global vars.
    
    # Store original global vars that inst_cert might overwrite, if needed for rollback or comparison
    local original_hy_domain="$hy_domain" 
    local original_cert_path="$cert_path"
    local original_key_path="$key_path"

    inst_cert # This function will ask for new cert type and set new $cert_path, $key_path, $hy_domain

    if [[ "$original_cert_path" == "$cert_path" && "$original_key_path" == "$key_path" ]]; then
        yellow "证书路径未发生变化。"
        # Optionally ask if they want to proceed with restart anyway
    fi

    sed -i "s|cert: $old_cert|cert: $cert_path|g" /etc/hysteria/config.yaml
    sed -i "s|key: $old_key|key: $key_path|g" /etc/hysteria/config.yaml
    sed -i "s/sni: $old_hydomain/sni: $hy_domain/g" /root/hy/hy-client.yaml
    sed -i "s/\"sni\": \"$old_hydomain\"/\"sni\": \"$hy_domain\"/g" /root/hy/hy-client.json
    
    # Update SNI in URL
    local old_url_sni_part="sni=$old_hydomain"
    local new_url_sni_part="sni=$hy_domain"
    sed -i "s/$old_url_sni_part/$new_url_sni_part/g" /root/hy/url.txt


    systemctl restart hysteria-server.service
    if [[ -n $(systemctl status hysteria-server.service 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 节点证书信息已成功修改。"
        yellow "客户端配置文件和分享链接中的SNI已更新。"
        showconf
    else
        red "Hysteria 2 服务重启失败，证书更改可能未生效。请检查日志。"
        # Potentially revert changes if restart fails? More complex.
    fi
}

changeproxysite(){
    local oldproxysite=$(grep -oP 'url: https://\K\S+' /etc/hysteria/config.yaml)
    if [[ -z "$oldproxysite" ]]; then
        red "错误：无法从配置文件中读取旧的伪装网站。"
        return 1
    fi
    
    inst_site # This function sets $proxysite

    sed -i "s|url: https://$oldproxysite|url: https://$proxysite|g" /etc/hysteria/config.yaml

    systemctl restart hysteria-server.service
    if [[ -n $(systemctl status hysteria-server.service 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 节点伪装网站已成功修改为：$proxysite"
    else
        red "Hysteria 2 服务重启失败，伪装网站更改可能未生效。请检查日志。"
    fi
}

changeconf(){
    green "Hysteria 2 配置变更选择如下:"
    echo -e " ${GREEN}1.${PLAIN} 修改端口"
    echo -e " ${GREEN}2.${PLAIN} 修改密码"
    echo -e " ${GREEN}3.${PLAIN} 修改证书" # Merged cert type and path into one
    echo -e " ${GREEN}4.${PLAIN} 修改伪装网站"
    echo ""
    read -p " 请选择操作 [1-4] (其他输入则返回主菜单)：" confAnswer
    case $confAnswer in
        1 ) changeport ;;
        2 ) changepasswd ;;
        3 ) change_cert ;;
        4 ) changeproxysite ;;
        * ) menu ;;
    esac
    echo ""
    read -n 1 -s -r -p "按任意键返回配置修改菜单..."
    changeconf
}

showconf(){
    if [[ ! -f /root/hy/hy-client.yaml ]]; then
        red "Hysteria 2 尚未安装或配置文件不存在。"
        return
    fi
    realip # Get current IP for display
    local display_ip="$ip"
    if [[ "$ip" == *":"* ]]; then
        display_ip="[$ip]"
    fi

    green "--- Hysteria 2 服务器配置 (/etc/hysteria/config.yaml) ---"
    cat /etc/hysteria/config.yaml
    green "---------------------------------------------------------"
    echo ""
    yellow "Hysteria 2 客户端 YAML 配置文件 (/root/hy/hy-client.yaml):"
    red "$(cat /root/hy/hy-client.yaml)"
    echo ""
    yellow "Hysteria 2 客户端 JSON 配置文件 (/root/hy/hy-client.json):"
    red "$(cat /root/hy/hy-client.json)"
    echo ""
    yellow "Hysteria 2 节点分享链接 (/root/hy/url.txt):"
    local current_url=$(cat /root/hy/url.txt)
    red "$current_url"
    echo ""
    yellow "二维码分享链接 (内容同上):"
    qrencode -t ANSIUTF8 "$current_url"
}

menu() {
    clear
    echo "#############################################################"
    echo -e "#         ${GREEN}Hysteria 2 一键安装脚本 (增强版)${PLAIN}         #"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} ${GREEN}安装 Hysteria 2${PLAIN}"
    echo -e " ${RED}2.${PLAIN} ${RED}卸载 Hysteria 2${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " 3. Hysteria 2 服务管理 (启/停/重启/状态/日志)"
    echo -e " 4. 修改 Hysteria 2 配置 (端/密/证/伪)"
    echo -e " 5. 显示 Hysteria 2 配置文件和分享链接"
    echo " ------------------------------------------------------------"
    echo -e " 0. 退出脚本"
    echo ""
    # Check if Hysteria is installed
    if [[ -f "/etc/hysteria/config.yaml" ]]; then
        green "Hysteria 2 当前状态: $(systemctl is-active hysteria-server.service)"
        local current_port=$(grep -oP 'listen: : *\K[0-9]+' /etc/hysteria/config.yaml 2>/dev/null)
        local current_sni=$(grep -oP 'sni: \K\S+' /root/hy/hy-client.yaml 2>/dev/null || echo "N/A")
        yellow "监听端口: $current_port, SNI: $current_sni"
    else
        yellow "Hysteria 2 似乎未安装。"
    fi
    echo ""
    read -rp "请输入选项 [0-5]: " menuInput
    case $menuInput in
        1 ) insthysteria ;;
        2 ) unsthysteria ;;
        3 ) hysteriaswitch ;;
        4 ) 
            if [[ ! -f "/etc/hysteria/config.yaml" ]]; then
                red "Hysteria 2 未安装，无法修改配置。"
                sleep 2
            else
                changeconf
            fi
            ;;
        5 ) 
            if [[ ! -f "/etc/hysteria/config.yaml" ]]; then
                red "Hysteria 2 未安装，无法显示配置。"
                sleep 2
            else
                showconf
            fi
            ;;
        0 ) exit 0 ;;
        * ) red "无效输入!" && sleep 1 ;;
    esac
    menu # Loop back to menu
}

# Main execution
menu
