#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

# --- Global variable declarations ---
ip=""
cert_path="/etc/hysteria/cert.crt" # Target path for cert
key_path="/etc/hysteria/private.key" # Target path for key
hy_domain="" # SNI domain, set during cert installation
domain=""    # Domain for cert, used by inst_cert
port=""
firstport=""
endport=""
auth_pwd=""
proxysite=""
SYSTEMD_SERVICE_NAME=""
PORT_JUMP_COMMENT="hysteria_jump_rule_v2" # Comment for iptables port jump rules
PACKAGE_UPDATE_RUN_ONCE_FLAG=""

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

# --- Prerequisite Checks ---
[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

if ! grep -q -E "Debian GNU/Linux 12|VERSION_ID=\"12\"" /etc/os-release; then
    red "错误: 此脚本设计为在 Debian 12 上运行。"
    yellow "您的系统似乎不是 Debian 12。继续运行可能会导致未知问题。"
    read -rp "您确定要继续吗? (y/N): " confirm_continue
    if [[ ! "$confirm_continue" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# --- Utility Functions ---
ensure_tool() {
    local tool_cmd_to_check="$1"
    local package_to_install="$2"
    local found_by_type_p=false
    local found_by_direct_path=false

    if type -P "$tool_cmd_to_check" >/dev/null 2>&1; then
        found_by_type_p=true
    fi
    # Specific check for netfilter-persistent location
    if [[ "$tool_cmd_to_check" == "netfilter-persistent" && -x "/usr/sbin/netfilter-persistent" ]]; then
        found_by_direct_path=true
    fi

    if $found_by_type_p || $found_by_direct_path; then
        return 0 # Tool already found
    fi

    yellow "$tool_cmd_to_check 未找到，正在尝试安装包 $package_to_install..."
    if [[ -z "$PACKAGE_UPDATE_RUN_ONCE_FLAG" ]]; then
        apt-get update -qq
        export PACKAGE_UPDATE_RUN_ONCE_FLAG="true" # Ensure apt update runs only once
    fi

    if ! apt -y -qq install "$package_to_install"; then
        red "包 $package_to_install 安装失败。"
        if [[ "$package_to_install" == "iptables-persistent" ]]; then
            yellow "iptables-persistent 包安装失败。防火墙规则持久化可能依赖旧的 iptables-save 方法。"
            # Do not exit, allow fallback
        else
            exit 1 # Exit for other critical packages
        fi
    else
        green "$package_to_install 包已安装/已是最新版。"
    fi

    # Re-check after installation attempt
    if type -P "$tool_cmd_to_check" >/dev/null 2>&1; then
        green "$tool_cmd_to_check (来自包 $package_to_install) 安装成功且在 PATH 中。"
    elif [[ "$tool_cmd_to_check" == "netfilter-persistent" && -x "/usr/sbin/netfilter-persistent" ]]; then
        green "$tool_cmd_to_check (在 /usr/sbin/netfilter-persistent 找到) 安装/验证成功。"
    elif [[ "$tool_cmd_to_check" == "netfilter-persistent" ]]; then # netfilter-persistent handled with a specific warning
        yellow "警告: $package_to_install 包已处理, 但 $tool_cmd_to_check 命令不在标准PATH或/usr/sbin/中。"
        yellow "脚本将尝试使用旧的 iptables-save 方法进行防火墙规则持久化 (如果需要)。"
    else
        red "$tool_cmd_to_check (尝试从包 $package_to_install 安装) 后仍未找到。请检查安装。" && exit 1
    fi
}

# Ensure essential tools are available early
ensure_tool "curl" "curl"
ensure_tool "dig" "dnsutils"
ensure_tool "realpath" "coreutils" # Often available, but good to check
ensure_tool "openssl" "openssl"
ensure_tool "iptables" "iptables"
ensure_tool "netfilter-persistent" "iptables-persistent" # Handles netfilter-persistent/iptables-persistent

realip(){
    # Attempt to get IPv4 address first
    ip=$(curl -s4m8 ip.sb -k)
    if [[ -z "$ip" ]]; then
        # Fallback to IPv6 if IPv4 fails
        ip=$(curl -s6m8 ip.sb -k)
    fi
}

get_systemd_service_name(){
    if systemctl list-unit-files | grep -qw hysteria-server.service; then
        SYSTEMD_SERVICE_NAME="hysteria-server.service"
    elif systemctl list-unit-files | grep -qw hysteria.service; then
        SYSTEMD_SERVICE_NAME="hysteria.service"
    else
        SYSTEMD_SERVICE_NAME="" # Explicitly set to empty if not found
    fi
}

# --- Core Logic Functions ---

inst_cert(){
    green "Hysteria 2 将通过 ACME.sh 脚本自动申请证书。"

    local target_cert_dir="/etc/hysteria" # Defined globally but good to have local for clarity
    local ca_log_path="$target_cert_dir/ca.log" # Stores the domain for which cert was issued

    mkdir -p "$target_cert_dir"
    # chmod a+x "$HOME" # Removed: Unnecessary and broad permission change

    local previous_domain_from_log=""
    if [[ -f "$ca_log_path" ]]; then
        previous_domain_from_log=$(cat "$ca_log_path")
    fi

    # Check for existing certificates and ask user
    if [[ -f "$cert_path" && -f "$key_path" ]] && [[ -s "$cert_path" && -s "$key_path" ]] && [[ -n "$previous_domain_from_log" ]]; then
        read -rp "检测到域名 '$previous_domain_from_log' 的现有证书。是否继续使用并尝试续期此域名？(Y/n)，或输入新域名: " domain_choice
        if [[ -z "$domain_choice" || "$domain_choice" =~ ^[Yy]$ ]]; then
            domain="$previous_domain_from_log"
            green "将为域名 '$domain' 尝试续期/验证证书。"
        elif [[ "$domain_choice" =~ ^[Nn]$ ]]; then
            read -p "请输入需要申请证书的新域名：" domain_input_for_acme
            domain="$domain_input_for_acme"
        else
            domain="$domain_choice" # User typed a new domain directly
        fi
    else
        read -p "请输入需要申请证书的域名：" domain_input_for_acme
        domain="$domain_input_for_acme"
    fi

    [[ -z "$domain" ]] && red "未输入域名！证书申请中止。" && return 1
    green "准备为域名 '$domain' 申请ACME证书 (将保存到 $target_cert_dir)..."
    hy_domain="$domain" # Set global hy_domain for SNI

    # WARP detection and handling to get real IP
    local WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    local WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    local temp_server_ipv4=""
    local temp_server_ipv6=""

    yellow "正在检测服务器公网IP地址..."
    if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
        green "检测到WARP已激活，临时停用WARP以获取真实IP..."
        wg-quick down wgcf >/dev/null 2>&1; systemctl stop warp-go >/dev/null 2>&1; sleep 3 # Wait for network to settle
        temp_server_ipv4=$(curl -s4m8 ip.sb -k); temp_server_ipv6=$(curl -s6m8 ip.sb -k)
        green "尝试重新激活WARP...";
        # Re-activate WARP if it was active
        if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then # Re-check status variables
             wg-quick up wgcf >/dev/null 2>&1; systemctl start warp-go >/dev/null 2>&1
        fi
    else
        temp_server_ipv4=$(curl -s4m8 ip.sb -k); temp_server_ipv6=$(curl -s6m8 ip.sb -k)
    fi

    if [[ -z "$temp_server_ipv4" && -z "$temp_server_ipv6" ]]; then red "错误：无法获取服务器公网IP！"; return 1; fi
    yellow "检测到服务器公网IPs: IPv4: ${temp_server_ipv4:-N/A}, IPv6: ${temp_server_ipv6:-N/A}"

    yellow "正在解析域名 '$domain' 的DNS记录..."
    local domain_a_record_ip=$(dig A +short "$domain" | head -n1)
    local domain_aaaa_record_ip=$(dig AAAA +short "$domain" | head -n1)
    local is_ipv6_validation_for_acme=false # Flag to use IPv6 for ACME standalone listener

    # Validate domain DNS against server IP
    if [[ -n "$temp_server_ipv4" && -n "$domain_a_record_ip" && "$domain_a_record_ip" == "$temp_server_ipv4" ]]; then
        ip="$temp_server_ipv4"; is_ipv6_validation_for_acme=false # Update global IP
        green "验证成功: 域名 '$domain' A记录 ($domain_a_record_ip) -> 服务器 IPv4 ($ip)."
    elif [[ -n "$temp_server_ipv6" && -n "$domain_aaaa_record_ip" && "$domain_aaaa_record_ip" == "$temp_server_ipv6" ]]; then
        ip="$temp_server_ipv6"; is_ipv6_validation_for_acme=true # Update global IP
        green "验证成功: 域名 '$domain' AAAA记录 ($domain_aaaa_record_ip) -> 服务器 IPv6 ($ip)."
    else
        red "错误：域名DNS记录与服务器IP不匹配或无法解析。"; yellow "详情: SrvIP4:${temp_server_ipv4:-无} SrvIP6:${temp_server_ipv6:-无} DomA:${domain_a_record_ip:-无} DomAAAA:${domain_aaaa_record_ip:-无}"; return 1
    fi

    # Install necessary packages for ACME.sh and cron
    apt -y -qq install curl wget sudo socat openssl dnsutils cron # Ensure cron is installed
    local cron_daemon_name="cron" # Debian uses "cron"
    systemctl start "$cron_daemon_name" 2>/dev/null ; systemctl enable "$cron_daemon_name" 2>/dev/null

    # Install or upgrade ACME.sh
    local ACME_SH_PATH="$HOME/.acme.sh/acme.sh"
    if [[ ! -f "$ACME_SH_PATH" ]]; then
        yellow "$ACME_SH_PATH 未找到。安装acme.sh..."; mkdir -p "$HOME/.acme.sh" # Ensure dir exists
        # Generate a random-ish email for ACME registration
        if curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com; then green "acme.sh 安装成功。"; else red "acme.sh 安装失败。"; return 1; fi
        # Try to source .bashrc to make acme.sh available if it modified PATH, though direct path is preferred
        if [[ -f "$HOME/.bashrc" ]]; then source "$HOME/.bashrc"; fi
    fi
    if [[ ! -f "$ACME_SH_PATH" ]]; then red "$ACME_SH_PATH 文件不存在。acme.sh 安装可能不完整。"; return 1; fi
    if [[ ! -x "$ACME_SH_PATH" ]]; then yellow "$ACME_SH_PATH 不可执行。尝试chmod +x..."; chmod +x "$ACME_SH_PATH"; if [[ ! -x "$ACME_SH_PATH" ]]; then red "未能使 $ACME_SH_PATH 可执行。"; return 1; fi; fi

    "$ACME_SH_PATH" --upgrade --auto-upgrade # Upgrade acme.sh and enable auto-upgrade
    "$ACME_SH_PATH" --set-default-ca --server letsencrypt # Set Let's Encrypt as default CA

    green "为 '$domain' 申请证书 (使用 ${ip})..."
    local issue_cmd_status
    if $is_ipv6_validation_for_acme; then
        "$ACME_SH_PATH" --issue -d "${domain}" --standalone -k ec-256 --listen-v6 # Removed --insecure
        issue_cmd_status=$?
    else
        "$ACME_SH_PATH" --issue -d "${domain}" --standalone -k ec-256 # Removed --insecure
        issue_cmd_status=$?
    fi
    if [[ $issue_cmd_status -ne 0 ]]; then red "acme.sh --issue 失败，码: $issue_cmd_status。"; return 1; fi
    green "证书签发命令为 '$domain' 执行完毕。"

    green "安装 '$domain' 的证书到 $target_cert_dir ..."
    # Install cert to target paths (key_path, cert_path are global)
    if "$ACME_SH_PATH" --install-cert -d "${domain}" --key-file "$key_path" --fullchain-file "$cert_path" --ecc; then
        if [[ -f "$cert_path" && -f "$key_path" ]] && [[ -s "$cert_path" && -s "$key_path" ]]; then
            echo "$domain" > "$ca_log_path" # Log the successfully processed domain

            # Set secure permissions for key and certificate
            chmod 600 "$key_path"
            chmod 644 "$cert_path"
            chown root:root "$key_path" "$cert_path" # Ensure root ownership
            green "私钥权限设置为 600, 证书权限设置为 644. Ownership set to root."

            green "正在尝试设置acme.sh证书自动续签的cron任务..."
            local cron_service_active=false
            if systemctl is-active --quiet "$cron_daemon_name"; then
                green "Cron服务 ($cron_daemon_name) 正在运行。"
                cron_service_active=true
            else
                yellow "警告: Cron服务 ($cron_daemon_name) 当前未运行。正在尝试启动..."
                systemctl start "$cron_daemon_name"; sleep 2 # Give it time to start
                if systemctl is-active --quiet "$cron_daemon_name"; then green "Cron服务 ($cron_daemon_name) 已成功启动。"; cron_service_active=true;
                else red "错误: 无法启动Cron服务 ($cron_daemon_name)。自动续签将无法工作。"; fi
            fi

            local cron_job_set_successfully=false
            if $cron_service_active; then
                local current_crontab_content=$(crontab -l 2>/dev/null)
                # Ensure acme.sh cron command is correctly quoted for the crontab entry
                local acme_cron_cmd=$(printf "0 0 * * * %s --cron -f >/dev/null 2>&1" "\"$ACME_SH_PATH\"")
                # Remove any old acme.sh cron job lines to prevent duplicates, then add the new one
                local new_crontab_content=$(echo -e "${current_crontab_content}" | grep -vF "\"$ACME_SH_PATH\" --cron")
                new_crontab_content=$(echo -e "${new_crontab_content}\n${acme_cron_cmd}" | sed '/^$/d') # Remove blank lines
                if echo "${new_crontab_content}" | crontab -; then green "用户crontab更新成功 (尝试)。"; fi
                sleep 1 # Brief pause
                # Verify cron job was set
                if crontab -l 2>/dev/null | grep -qF "\"$ACME_SH_PATH\" --cron" ; then
                    green "acme.sh 证书自动续签的cron任务已成功设置/验证。"; cron_job_set_successfully=true;
                fi
            fi
            if ! $cron_job_set_successfully; then
                yellow "警告: 未能自动设置acme.sh的cron续签任务。"
                yellow "请手动添加以下行到root用户的crontab: 0 0 * * * \"$ACME_SH_PATH\" --cron -f >/dev/null 2>&1"
            fi
            green "证书申请与安装成功!"; yellow "证书: $cert_path, 私钥: $key_path"
        else red "证书文件 ($cert_path, $key_path) 未生成或为空。"; return 1; fi
    else red "acme.sh --install-cert 失败。"; return 1; fi
    return 0
}

inst_port(){
    read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port_input
    [[ -z "$port_input" ]] && port_input=$(shuf -i 2000-65535 -n 1)
    port="$port_input" # Set global port

    # Check if port is already in use (UDP)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port_input
            [[ -z "$port_input" ]] && port_input=$(shuf -i 2000-65535 -n 1)
            port="$port_input"
        fi
    done
    yellow "将在 Hysteria 2 节点使用的端口是：$port"
    inst_jump # Proceed to port jump configuration
}

inst_jump(){
    green "Hysteria 2 端口使用模式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 单端口 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 端口跳跃"
    echo ""
    read -rp "请输入选项 [1-2]: " jumpInput

    # Clear existing jump rules managed by this script (identified by comment)
    # Using grep -oP to get the rule arguments for -D. This works for the specific rules this script adds.
    while IFS= read -r rule_line_args; do
      [[ -n "$rule_line_args" ]] && iptables -t nat -D $rule_line_args
    done < <(iptables-save -t nat | grep -oP "PREROUTING .* --comment \"$PORT_JUMP_COMMENT\"" || true)

    while IFS= read -r rule_line_args; do
      [[ -n "$rule_line_args" ]] && ip6tables -t nat -D $rule_line_args
    done < <(ip6tables-save -t nat | grep -oP "PREROUTING .* --comment \"$PORT_JUMP_COMMENT\"" || true)

    if [[ $jumpInput == 2 ]]; then
        read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport_input
        read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport_input

        # Validate port inputs
        if ! [[ "$firstport_input" =~ ^[0-9]+$ && "$firstport_input" -ge 1 && "$firstport_input" -le 65535 ]] || \
           ! [[ "$endport_input" =~ ^[0-9]+$ && "$endport_input" -ge 1 && "$endport_input" -le 65535 ]]; then
            red "错误：起始端口和末尾端口必须是1-65535之间的数字。"; firstport=""; endport=""; # Clear invalid ports
        elif [[ "$firstport_input" -ge "$endport_input" ]]; then
            red "错误：起始端口必须小于末尾端口。"; firstport=""; endport=""; # Clear invalid ports
        else
            firstport="$firstport_input"; endport="$endport_input" # Set global firstport and endport
        fi

        if [[ -n "$firstport" && -n "$endport" ]]; then
            yellow "设置端口跳跃: $firstport:$endport -> $port"
            iptables -t nat -A PREROUTING -p udp --dport "$firstport:$endport" -j DNAT --to-destination ":$port" -m comment --comment "$PORT_JUMP_COMMENT"
            ip6tables -t nat -A PREROUTING -p udp --dport "$firstport:$endport" -j DNAT --to-destination ":$port" -m comment --comment "$PORT_JUMP_COMMENT"

            # Persist iptables rules
            if command -v netfilter-persistent >/dev/null 2>&1; then
                netfilter-persistent save >/dev/null 2>&1
                green "iptables规则已尝试使用 netfilter-persistent 保存。"
            elif command -v iptables-save >/dev/null 2>&1 && command -v ip6tables-save >/dev/null 2>&1; then
                mkdir -p /etc/iptables; iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6
                green "iptables规则已尝试保存到 /etc/iptables/"
            else
                yellow "警告: 未找到netfilter-persistent或iptables-save，防火墙规则可能在重启后丢失。"
            fi
        else red "端口跳跃设置无效或已跳过。"; unset firstport; unset endport; fi # Ensure vars are unset if invalid
    else red "将继续使用单端口模式"; unset firstport; unset endport; fi # Ensure vars are unset for single port mode
}

inst_pwd(){
    read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" pwd_input
    [[ -z "$pwd_input" ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-16) || auth_pwd="$pwd_input" # Longer random pwd
    yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
}

inst_site(){
    read -rp "请输入 Hysteria 2 的伪装网站地址 （去除https://） [默认 en.snu.ac.kr]：" site_input
    [[ -z "$site_input" ]] && proxysite="en.snu.ac.kr" || proxysite="$site_input"
    yellow "使用在 Hysteria 2 节点的伪装网站为：$proxysite"
}

insthysteria(){
    realip # Get public IP
    [[ -z "$ip" ]] && red "错误：无法获取服务器的公网IP地址！ Hysteria安装中止。" && exit 1
    yellow "脚本初步检测到服务器IP为: $ip (后续证书申请流程可能会根据DNS验证更新此IP)"

    # Ensure common tools are available for installation process
    ensure_tool "sudo" "sudo" # sudo might be needed by sub-scripts, though this script runs as root
    ensure_tool "ss" "procps" # For port checking
    ensure_tool "crontab" "cron" # For acme.sh cron job

    # Install Hysteria server if not already present
    if [[ ! -f "/usr/local/bin/hysteria" ]]; then
        # Download and execute the official/community installer script for Hysteria 2
        wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
        if [[ ! -f "install_server.sh" ]]; then red "错误：无法下载 Hysteria 2 安装脚本。"; exit 1; fi
        bash install_server.sh # This script is expected to install hysteria and setup systemd service
        rm -f install_server.sh # Clean up downloaded script
    else green "检测到 Hysteria 2 主程序已存在。"; fi

    if [[ -f "/usr/local/bin/hysteria" ]]; then green "Hysteria 2 主程序准备就绪！"; else red "Hysteria 2 主程序安装失败或未找到！"; exit 1; fi

    # Configure Certificate, Port, Password, Masquerade Site
    if ! inst_cert; then
        red "证书配置失败，安装中止。"
        exit 1
    fi
    inst_port
    inst_pwd
    inst_site

    # Final checks for necessary variables before writing config
    [[ -z "$ip" ]] && red "内部错误: IP ($ip) 未设置。" && exit 1
    [[ -z "$port" ]] && red "内部错误: Port ($port) 未设置。" && exit 1
    [[ -z "$auth_pwd" ]] && red "内部错误: Password ($auth_pwd) 未设置。" && exit 1
    [[ -z "$hy_domain" ]] && red "内部错误: SNI ($hy_domain) 未设置。" && exit 1
    [[ ! -f "$cert_path" || ! -f "$key_path" ]] && red "内部错误: 证书或密钥在 $cert_path / $key_path 未找到。" && exit 1

    # Create Hysteria server configuration
    mkdir -p /etc/hysteria # Ensure directory exists
    cat << EOF > /etc/hysteria/config.yaml
listen: :$port
tls:
  cert: $cert_path
  key: $key_path
quic: # Default QUIC parameters, consider making these configurable if needed
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
    rewriteHost: true # Typically true for masquerading
EOF

    # Client configuration will always use secure TLS with ACME certs
    local client_tls_insecure_bool_value="false"
    local client_tls_insecure_int_value="0" # 0 for false in share link
    green "客户端配置将使用 'insecure: $client_tls_insecure_bool_value' (证书将被验证)。"

    local config_port_for_client="$port"
    if [[ -n "$firstport" && -n "$endport" && "$firstport" -lt "$endport" ]]; then
        config_port_for_client="$port,$firstport-$endport" # Port hopping format for client
    fi
    local config_ip_for_client="$ip"
    if [[ "$ip" == *":"* ]]; then config_ip_for_client="[$ip]"; fi # Format IPv6 for client config

    mkdir -p /root/hy # Directory for client configs and share link
    # Client YAML config
    cat << EOF > /root/hy/hy-client.yaml
server: $config_ip_for_client:$config_port_for_client
auth: $auth_pwd
tls:
  sni: $hy_domain
  insecure: $client_tls_insecure_bool_value 
quic: {initStreamReceiveWindow: 16777216, maxStreamReceiveWindow: 16777216, initConnReceiveWindow: 33554432, maxConnReceiveWindow: 33554432}
fastOpen: true
socks5: {listen: 127.0.0.1:5678} # Default SOCKS5 listen address
transport: {udp: {hopInterval: 30s}} # Example transport option
EOF
    # Client JSON config
    cat << EOF > /root/hy/hy-client.json
{
  "server": "$config_ip_for_client:$config_port_for_client",
  "auth": "$auth_pwd",
  "tls": { "sni": "$hy_domain", "insecure": $client_tls_insecure_bool_value },
  "quic": {"initStreamReceiveWindow": 16777216, "maxStreamReceiveWindow": 16777216, "initConnReceiveWindow": 33554432, "maxConnReceiveWindow": 33554432},
  "socks5": {"listen": "127.0.0.1:5678"},
  "transport": {"udp": {"hopInterval": "30s"}}
}
EOF
    # Share Link
    local share_link_ip_formatted="$ip"
    if [[ "$ip" == *":"* ]]; then share_link_ip_formatted="[$ip]"; fi # Format IPv6 for share link

    local url="hysteria2://$auth_pwd@$share_link_ip_formatted:$config_port_for_client/?insecure=$client_tls_insecure_int_value&sni=$hy_domain#Hysteria2-Debian12-$(date +%m%d)"
    echo "$url" > /root/hy/url.txt

    # Reload, enable and restart Hysteria service
    systemctl daemon-reload
    get_systemd_service_name # Detect service name (hysteria.service or hysteria-server.service)
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then
        red "错误: 未找到Hysteria的systemd服务单元。请检查 install_server.sh 的安装过程。"; exit 1;
    fi

    systemctl enable "$SYSTEMD_SERVICE_NAME"
    systemctl restart "$SYSTEMD_SERVICE_NAME"

    # Verify service status
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 服务 ($SYSTEMD_SERVICE_NAME) 启动成功"
    else
        red "Hysteria 2 服务 ($SYSTEMD_SERVICE_NAME) 启动失败"; yellow "请运行 'systemctl status $SYSTEMD_SERVICE_NAME' 和 'journalctl -u $SYSTEMD_SERVICE_NAME -n 50 --no-pager' 查看日志。"; exit 1;
    fi
    red "======================================================================================"
    green "Hysteria 2 代理服务安装完成 (Debian 12 专用版)"
    showconf # Display configuration details
    echo ""
    yellow "重要: 如果您使用了端口跳跃，请确保客户端支持该格式的端口定义 (port,start-end)。"
}

unsthysteria(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then yellow "未检测到Hysteria服务单元。可能未安装或已被移除。"; else
        green "正在停止并禁用 Hysteria 服务 ($SYSTEMD_SERVICE_NAME)..."
        systemctl stop "$SYSTEMD_SERVICE_NAME" >/dev/null 2>&1
        systemctl disable "$SYSTEMD_SERVICE_NAME" >/dev/null 2>&1
        rm -f "/lib/systemd/system/$SYSTEMD_SERVICE_NAME" "/usr/lib/systemd/system/$SYSTEMD_SERVICE_NAME"
        # Remove potential template service files if they exist from other installers
        rm -f "/lib/systemd/system/hysteria-server@.service" "/usr/lib/systemd/system/hysteria-server@.service"
        systemctl daemon-reload
        green "Hysteria 服务 ($SYSTEMD_SERVICE_NAME) 已停止并禁用, systemd文件已移除。"
    fi

    green "正在移除 Hysteria 相关文件和目录..."
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy

    # Remove acme.sh cron job if it exists
    local acme_cron_cmd_pattern="\"$HOME/.acme.sh/acme.sh\" --cron" # Pattern to find the cron job
    if crontab -l 2>/dev/null | grep -qF "$acme_cron_cmd_pattern"; then
        green "正在移除acme.sh的cron任务..."
        (crontab -l 2>/dev/null | grep -vF "$acme_cron_cmd_pattern") | crontab -
        if ! crontab -l 2>/dev/null | grep -qF "$acme_cron_cmd_pattern"; then green "acme.sh cron任务已移除。"; else yellow "警告: acme.sh cron任务移除可能未成功。"; fi
    fi

    green "正在移除由本脚本添加的iptables端口跳跃规则 (带注释 $PORT_JUMP_COMMENT)..."
    # Clear existing jump rules (same logic as in inst_jump)
    while IFS= read -r rule_to_delete_args; do
      [[ -n "$rule_to_delete_args" ]] && iptables -t nat -D ${rule_to_delete_args}
    done < <(iptables-save -t nat | grep -oP "PREROUTING .* --comment \"$PORT_JUMP_COMMENT\"" || true)

    while IFS= read -r rule_to_delete_args; do
      [[ -n "$rule_to_delete_args" ]] && ip6tables -t nat -D ${rule_to_delete_args}
    done < <(ip6tables-save -t nat | grep -oP "PREROUTING .* --comment \"$PORT_JUMP_COMMENT\"" || true)

    # Persist changes to iptables rules
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1; green "iptables规则已尝试使用 netfilter-persistent 保存。"
    elif command -v iptables-save >/dev/null 2>&1 && command -v ip6tables-save >/dev/null 2>&1; then
        mkdir -p /etc/iptables; iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6
        green "iptables规则已尝试保存到 /etc/iptables/"
    fi

    read -rp "是否同时卸载acme.sh证书申请工具 (证书会保留在/etc/hysteria, 但acme工具本身移除)？[y/N]: " remove_acme
    if [[ "$remove_acme" =~ ^[Yy]$ ]]; then
        if command -v "$HOME/.acme.sh/acme.sh" &>/dev/null; then
            "$HOME/.acme.sh/acme.sh" --uninstall
            rm -rf "$HOME/.acme.sh" # Remove acme.sh directory
            green "acme.sh已卸载。"
        else yellow "未找到acme.sh。可能已被卸载或安装在非标准位置。"; fi
    fi
    green "Hysteria 2 已尝试彻底卸载完成！"
}

# --- Service Management Functions ---
starthysteria(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务未找到! 可能未安装。" && return; fi
    systemctl start "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then green "Hysteria 2 服务已启动。"; else
        red "Hysteria 2 服务启动失败。"; yellow "请运行 'systemctl status $SYSTEMD_SERVICE_NAME' 和 'journalctl -u $SYSTEMD_SERVICE_NAME -n 50 --no-pager' 查看日志。"; fi
}

stophysteria(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务未找到! 可能未安装。" && return; fi
    systemctl stop "$SYSTEMD_SERVICE_NAME"; green "Hysteria 2 服务已停止。"
}

hysteriaswitch(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" && "$1" != "menu_return" ]]; then # Allow returning to menu even if service name is lost temporarily
        red "Hysteria 服务未安装或无法确定服务名。"
        read -n 1 -s -r -p "按任意键返回主菜单..." && menu && return
    fi
    echo ""; yellow "Hysteria 2 服务管理 (服务: ${SYSTEMD_SERVICE_NAME:-未找到}):"
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"; echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"; echo -e " ${GREEN}4.${PLAIN} 查看 Hysteria 2 状态"
    echo -e " ${GREEN}5.${PLAIN} 查看 Hysteria 2 日志"; echo -e " ${GREEN}0.${PLAIN} 返回主菜单"; echo ""
    read -rp "请输入选项 [0-5]: " switchInput
    case $switchInput in
        1) starthysteria ;;
        2) stophysteria ;;
        3) if [[ -n "$SYSTEMD_SERVICE_NAME" ]]; then systemctl restart "$SYSTEMD_SERVICE_NAME"; green "Hysteria 2 服务已尝试重启。"; else red "服务名未知，无法重启。"; fi ;;
        4) if [[ -n "$SYSTEMD_SERVICE_NAME" ]]; then systemctl status "$SYSTEMD_SERVICE_NAME"; else red "服务名未知，无法查看状态。"; fi ;;
        5) if [[ -n "$SYSTEMD_SERVICE_NAME" ]]; then journalctl -u "$SYSTEMD_SERVICE_NAME" -n 50 --no-pager; else red "服务名未知，无法查看日志。"; fi ;;
        0) menu ;;
        *) red "无效输入!" ; sleep 1 ;;
    esac
    [[ "$switchInput" != "0" ]] && read -n 1 -s -r -p "按任意键返回操作菜单..." && hysteriaswitch "menu_return" # Pass arg to allow menu redisplay
}

# --- Configuration Modification Functions ---
change_cert(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装或配置文件不存在。" && return; fi
    get_systemd_service_name; if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知! 无法重启服务后应用更改。" && return; fi

    local old_hy_domain_client="N/A"; [[ -f /root/hy/hy-client.yaml ]] && old_hy_domain_client=$(grep -oP 'sni: \K\S+' /root/hy/hy-client.yaml || echo "N/A")
    local preserved_ip_before_cert_change="$ip" # Preserve current IP to check if it changes

    if ! inst_cert; then # This will re-run the certificate acquisition process
        red "证书更新/申请流程失败。"
        # Restore old IP if it was changed by a failed inst_cert attempt and preserved_ip is valid
        if [[ -n "$preserved_ip_before_cert_change" ]]; then ip="$preserved_ip_before_cert_change"; fi
        return 1
    fi

    # Update client configurations with the new SNI (hy_domain is updated by inst_cert)
    local escaped_old_sni=$(printf '%s\n' "$old_hy_domain_client" | sed 's/[][\\/.^$*]/\\&/g')
    local escaped_new_sni=$(printf '%s\n' "$hy_domain" | sed 's/[][\\/.^$*]/\\&/g')

    if [[ -f /root/hy/hy-client.yaml ]]; then sed -i "s/sni: $escaped_old_sni/sni: $escaped_new_sni/g" /root/hy/hy-client.yaml; fi
    if [[ -f /root/hy/hy-client.json ]]; then sed -i "s/\"sni\": \"$escaped_old_sni\"/\"sni\": \"$escaped_new_sni\"/g" /root/hy/hy-client.json; fi
    if [[ -f /root/hy/url.txt ]]; then sed -i "s/sni=$escaped_old_sni/sni=$escaped_new_sni/g" /root/hy/url.txt; fi

    # If IP changed during ACME validation (e.g., due to WARP or DNS propagation)
    if [[ "$ip" != "$preserved_ip_before_cert_change" && -n "$preserved_ip_before_cert_change" ]]; then
        yellow "服务器IP因ACME验证已更新为: $ip。更新客户端配置中的服务器地址..."
        local old_client_ip_f="$preserved_ip_before_cert_change"; if [[ "$preserved_ip_before_cert_change" == *":"* ]]; then old_client_ip_f="[$preserved_ip_before_cert_change]"; fi
        local new_client_ip_f="$ip"; if [[ "$ip" == *":"* ]]; then new_client_ip_f="[$ip]"; fi

        local esc_old_client_ip_f=$(printf '%s\n' "$old_client_ip_f" | sed 's/[][\\/.^$*]/\\&/g')
        local esc_new_client_ip_f=$(printf '%s\n' "$new_client_ip_f" | sed 's/[][\\/.^$*]/\\&/g')

        # Note: These sed commands for IP are simple string replacements. Complex IPs or formats might require more robust parsing.
        if [[ -f /root/hy/hy-client.yaml ]]; then sed -i "s|server: $esc_old_client_ip_f:|server: $esc_new_client_ip_f:|g" /root/hy/hy-client.yaml; fi
        if [[ -f /root/hy/hy-client.json ]]; then sed -i "s|\"server\": \"$esc_old_client_ip_f\":|\"server\": \"$esc_new_client_ip_f\":|g" /root/hy/hy-client.json; fi
        
        # For URL, need to handle @ before IP
        local escaped_old_ip_url_at="@$(printf '%s\n' "$old_client_ip_f" | sed 's/[][\\/.^$*]/\\&/g')"
        local escaped_new_ip_url_at="@$(printf '%s\n' "$new_client_ip_f" | sed 's/[][\\/.^$*]/\\&/g')"
        if [[ -f /root/hy/url.txt ]]; then sed -i "s|$escaped_old_ip_url_at|$escaped_new_ip_url_at|g" /root/hy/url.txt; fi
    fi

    # Client 'insecure' flag is always false (0) with ACME certificates
    if [[ -f /root/hy/hy-client.yaml ]]; then sed -i "s/insecure: \(true\|false\)/insecure: false/g" /root/hy/hy-client.yaml; fi
    if [[ -f /root/hy/hy-client.json ]]; then sed -i "s/\"insecure\": \(true\|false\)/\"insecure\": false/g" /root/hy/hy-client.json; fi
    if [[ -f /root/hy/url.txt ]]; then sed -i "s/insecure=[01]/insecure=0/g" /root/hy/url.txt; fi

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 节点证书信息已成功修改。服务已重启。"
        showconf
    else red "Hysteria 2 服务重启失败。请检查日志。"; fi
}

changeport(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装或配置文件不存在。" && return; fi
    get_systemd_service_name; if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知! 无法重启。" && return; fi

    local old_server_port=$(grep -oP 'listen: : *\K[0-9]+' /etc/hysteria/config.yaml 2>/dev/null)
    [[ -z "$old_server_port" ]] && red "无法读取旧端口从 /etc/hysteria/config.yaml。" && return 1

    read -p "当前监听端口: $old_server_port. 请输入新端口 [1-65535] (回车则随机分配)：" new_port_input
    local new_port="${new_port_input:-$(shuf -i 2000-65535 -n 1)}"

    if [[ "$new_port" != "$old_server_port" ]] && [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$new_port") ]]; then
        red "$new_port 端口已被其他程序占用！端口未更改。"
        return 1
    fi
    if ! [[ "$new_port" =~ ^[0-9]+$ && "$new_port" -ge 1 && "$new_port" -le 65535 ]]; then
        red "无效的端口号: $new_port. 端口未更改。"
        return 1
    fi

    sed -i "s/listen: :$old_server_port/listen: :$new_port/g" /etc/hysteria/config.yaml

    if [[ -z "$ip" ]]; then realip; fi # Ensure IP is available for client config update
    [[ -z "$ip" ]] && red "无法获取本机IP地址来更新客户端配置。服务器配置已改，但客户端配置可能不正确。" && return 1

    local client_ip_f="$ip"; if [[ "$ip" == *":"* ]]; then client_ip_f="[$ip]"; fi # IPv6 bracket formatting
    # Escape for sed LHS and for JSON string value
    local esc_client_ip_f_sed=$(printf '%s\n' "$client_ip_f" | sed 's/[][\\/.^$*]/\\&/g') # Escaped for sed pattern matching
    
    # Update client YAML (assumes format "server: ip:port" or "server: [ipv6]:port")
    if [[ -f /root/hy/hy-client.yaml ]]; then
        sed -i -E "s/(server:\s*$esc_client_ip_f_sed\s*):\s*$old_server_port/\1:$new_port/" /root/hy/hy-client.yaml
    fi
    # Update client JSON (assumes format ""server"": ""ip"":port" or ""server"": ""[ipv6]"":port")
    if [[ -f /root/hy/hy-client.json ]]; then
         # Need to ensure esc_client_ip_f_sed is suitable for matching inside JSON string quotes
        sed -i -E "s/(\"server\":\s*\"$esc_client_ip_f_sed\"\s*):\s*$old_server_port/\1:$new_port/" /root/hy/hy-client.json
    fi
    # Update share URL
    if [[ -f /root/hy/url.txt ]]; then
        local esc_at_client_ip_f_prefix="@$(printf '%s\n' "$client_ip_f" | sed 's/[][\\/.^$*]/\\&/g')" # For URL: @ip:port or @[ipv6]:port
        sed -i -E "s/(${esc_at_client_ip_f_prefix}\s*):\s*$old_server_port/\1:$new_port/" /root/hy/url.txt
    fi
    
    # Port jump rules are NOT automatically updated here. User needs to re-configure if main port changes.
    yellow "主要监听端口已修改。如果之前设置了端口跳跃，旧的跳跃规则仍然指向旧的主端口 $old_server_port。"
    yellow "您可能需要通过主菜单的配置选项重新设置端口跳跃规则以指向新的主端口 $new_port。"

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 监听端口已修改为：$new_port. 服务已重启。"; showconf
    else red "Hysteria 2 服务重启失败。请检查日志。"; fi
}

changepasswd(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装或配置文件不存在。" && return; fi
    get_systemd_service_name; if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知! 无法重启。" && return; fi

    local oldpasswd=$(grep -oP 'password: \K\S+' /etc/hysteria/config.yaml 2>/dev/null)
    [[ -z "$oldpasswd" ]] && red "无法读取旧密码从 /etc/hysteria/config.yaml。" && return 1

    read -p "当前密码: $oldpasswd. 请输入新密码 (回车则随机生成)：" new_passwd_input
    local new_passwd="${new_passwd_input:-$(date +%s%N | md5sum | cut -c 1-16)}" # Longer random pwd

    # Escape old password for sed, as it might contain special characters
    local esc_oldpasswd_sed=$(printf '%s\n' "$oldpasswd" | sed 's/[&/\]/\\&/g') # Basic escaping for sed RHS
    sed -i "s/password: $esc_oldpasswd_sed/password: $new_passwd/g" /etc/hysteria/config.yaml

    if [[ -f /root/hy/hy-client.yaml ]]; then sed -i "s/auth: $esc_oldpasswd_sed/auth: $new_passwd/g" /root/hy/hy-client.yaml; fi
    if [[ -f /root/hy/hy-client.json ]]; then sed -i "s/\"auth\": \"$esc_oldpasswd_sed\"/\"auth\": \"$new_passwd\"/g" /root/hy/hy-client.json; fi
    
    if [[ -f /root/hy/url.txt ]]; then
        # For URL: hysteria2://PASSWORD@...
        local escaped_old_auth_url_prefix="hysteria2:\/\/$(printf '%s\n' "$oldpasswd" | sed 's/[][\\/.^$*&]/\\&/g')@" # Escape for sed pattern
        local new_auth_url_prefix="hysteria2://$new_passwd@"
        sed -i "s#$escaped_old_auth_url_prefix#$new_auth_url_prefix#g" /root/hy/url.txt # Use # as delimiter
    fi

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 密码已修改为：$new_passwd. 服务已重启。"; showconf
    else red "Hysteria 2 服务重启失败。请检查日志。"; fi
}

changeproxysite(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装或配置文件不存在。" && return; fi
    get_systemd_service_name; if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知! 无法重启。" && return; fi

    local oldproxysite=$(grep -oP 'url: https://\K\S+' /etc/hysteria/config.yaml)
    [[ -z "$oldproxysite" ]] && red "无法读取旧伪装网站从 /etc/hysteria/config.yaml。" && return 1
    
    # Call inst_site to get the new proxysite value (it sets global $proxysite)
    inst_site 
    [[ -z "$proxysite" ]] && red "未提供新的伪装网站地址。" && return 1


    # Escape for sed, as domain names can contain dots.
    local esc_old=$(printf '%s\n' "$oldproxysite" | sed 's/[&/\]/\\&/g ; s/\./\\./g')
    local esc_new=$(printf '%s\n' "$proxysite"    | sed 's/[&/\]/\\&/g ; s/\./\\./g')
    sed -i "s|url: https://$esc_old|url: https://$esc_new|g" /etc/hysteria/config.yaml

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 伪装网站已修改为：$proxysite. 服务已重启。"
    else red "Hysteria 2 服务重启失败。请检查日志。"; fi
}

changeconf(){
    if [[ ! -f "/etc/hysteria/config.yaml" ]]; then
        red "Hysteria 2 未安装。无法修改配置。"
        read -n 1 -s -r -p "按任意键返回主菜单..." && menu && return
    fi
    echo ""; green "Hysteria 2 配置变更选择 (Debian 12 专用版):"
    echo -e " ${GREEN}1.${PLAIN} 修改监听端口 (注意: 不会自动更新端口跳跃规则)"
    echo -e " ${GREEN}2.${PLAIN} 修改连接密码"
    echo -e " ${GREEN}3.${PLAIN} 修改/重新申请ACME证书 (SNI)"
    echo -e " ${GREEN}4.${PLAIN} 修改伪装网站"
    echo -e " ${GREEN}5.${PLAIN} 重新配置端口跳跃规则" # Added option for port jump
    echo -e " ${GREEN}0.${PLAIN} 返回主菜单"; echo ""
    read -p " 请选择操作 [0-5]：" confAnswer
    case $confAnswer in
        1) changeport ;;
        2) changepasswd ;;
        3) change_cert ;;
        4) changeproxysite ;;
        5) # Reconfigure port jump. Needs port to be set.
           if [[ -z "$port" ]]; then # If global port is not set, try to read from config
                port=$(grep -oP 'listen: : *\K[0-9]+' /etc/hysteria/config.yaml 2>/dev/null)
           fi
           if [[ -n "$port" ]]; then
                yellow "当前 Hysteria 主监听端口为: $port. 将基于此端口配置跳跃规则。"
                inst_jump # inst_jump clears old rules and sets new ones.
           else
                red "无法确定当前 Hysteria 监听端口。请先确保 Hysteria 已配置端口。"
           fi
           ;;
        0) menu ;;
        *) red "无效输入!"; sleep 1 ;;
    esac
    [[ "$confAnswer" != "0" ]] && read -n 1 -s -r -p "按任意键返回配置修改菜单..." && changeconf
}

showconf(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 2 未安装或配置文件不存在。" && return; fi
    get_systemd_service_name # Ensure SYSTEMD_SERVICE_NAME is up-to-date
    echo ""; green "--- Hysteria 2 服务器配置 (/etc/hysteria/config.yaml) (服务: ${SYSTEMD_SERVICE_NAME:-未知}) ---"
    cat /etc/hysteria/config.yaml
    echo ""; green "----------------------------------------------------------------------------------"
    if [[ -f /root/hy/hy-client.yaml ]]; then
        echo ""; yellow "客户端 YAML (/root/hy/hy-client.yaml):"; cat /root/hy/hy-client.yaml
    fi
    if [[ -f /root/hy/hy-client.json ]]; then
        echo ""; yellow "客户端 JSON (/root/hy/hy-client.json):"; cat /root/hy/hy-client.json
    fi
    if [[ -f /root/hy/url.txt ]]; then
        echo ""; yellow "分享链接 (/root/hy/url.txt):"; local current_url=$(cat /root/hy/url.txt); echo "$current_url"
        # QR Code display was previously removed, keeping it that way.
        # If QR code is desired, 'qrencode' package and its usage would be needed here.
    fi
}

# --- Main Menu ---
menu() {
    clear
    echo "#############################################################"
    echo -e "#     ${GREEN}Hysteria 2 一键安装脚本 (Debian 12 专用版)${PLAIN}       #"
    echo -e "#       ${YELLOW}作者: Misaka, Gemini (精简/改进版)${PLAIN}          #"
    echo "#############################################################"
    echo ""; echo -e " ${GREEN}1.${PLAIN} 安装 Hysteria 2"; echo -e " ${RED}2.${PLAIN} 卸载 Hysteria 2"
    echo " ------------------------------------------------------------"
    echo -e " ${GREEN}3.${PLAIN} Hysteria 2 服务管理"; echo -e " ${GREEN}4.${PLAIN} 修改 Hysteria 2 配置"
    echo -e " ${GREEN}5.${PLAIN} 显示配置文件和链接"; echo " ------------------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 退出脚本"; echo ""

    get_systemd_service_name # Update service status info
    if [[ -f "/etc/hysteria/config.yaml" && -n "$SYSTEMD_SERVICE_NAME" ]]; then
        local current_status=$(systemctl is-active "$SYSTEMD_SERVICE_NAME" 2>/dev/null)
        if [[ "$current_status" == "active" ]]; then green "Hysteria 2 状态: $current_status (运行中)"
        elif [[ "$current_status" == "inactive" || "$current_status" == "failed" ]]; then yellow "Hysteria 2 状态: $current_status"
        else yellow "Hysteria 2 状态: 未知 (is-active: '$current_status')"; fi
        
        local cp=$(grep -oP 'listen: : *\K[0-9]+' /etc/hysteria/config.yaml 2>/dev/null)
        local cs="N/A"; [[ -f /root/hy/hy-client.yaml ]] && cs=$(grep -oP 'sni: \K\S+' /root/hy/hy-client.yaml 2>/dev/null || echo N/A)
        yellow "监听端口: ${cp:-N/A}, SNI: ${cs:-N/A}"
    elif [[ -f "/etc/hysteria/config.yaml" ]]; then yellow "Hysteria配置文件存在但服务名未知 (可能服务单元文件丢失)。";
    else yellow "Hysteria 2 似乎未安装。"; fi
    echo ""
    read -rp "请输入选项 [0-5]: " menuInput
    case $menuInput in
        1) insthysteria ;;
        2) unsthysteria ;;
        3) hysteriaswitch ;;
        4) changeconf ;;
        5) showconf ;;
        0) echo "退出脚本。" && exit 0 ;;
        *) red "无效输入!" && sleep 1 ;;
    esac
    # Loop back to menu unless exiting
    [[ "$menuInput" != "0" ]] && read -n 1 -s -r -p "按任意键返回主菜单..." && menu
}

# --- Main execution ---
menu