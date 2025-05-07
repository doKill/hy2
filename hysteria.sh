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

# --- Global variable declarations ---
ip=""
cert_path=""
key_path=""
hy_domain=""
domain=""
port=""
firstport=""
endport=""
auth_pwd=""
proxysite=""
SYSTEMD_SERVICE_NAME=""
USE_INSECURE_CLIENT_CONFIG="true"
PORT_JUMP_COMMENT="hysteria_jump_rule_v2"

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1

ensure_tool() {
    local tool_name="$1"
    local package_name="$2"
    if [[ -z $(type -P "$tool_name") ]]; then
        yellow "$tool_name 未安装，正在尝试安装 $package_name..."
        # Avoid redundant updates on yum systems unless absolutely necessary
        if [[ ! "$SYSTEM" == "CentOS" && ! "$SYSTEM" == "Fedora" && ! "$SYSTEM" == "Rocky" && ! "$SYSTEM" == "Alma" ]]; then ${PACKAGE_UPDATE[int]}; fi
        ${PACKAGE_INSTALL[int]} "$package_name" || (red "$tool_name ($package_name) 安装失败，请手动安装后再运行脚本。" && exit 1)
        # Verify again after install attempt
        if [[ -z $(type -P "$tool_name") ]]; then red "$tool_name 安装后仍未找到，请检查安装。" && exit 1; fi
        green "$tool_name 安装成功。"
    fi
}

# Ensure essential tools are available early
ensure_tool "curl" "curl"
# For dig:
if [[ "$SYSTEM" == "CentOS" || "$SYSTEM" == "Fedora" || "$SYSTEM" == "Rocky" || "$SYSTEM" == "Alma" ]]; then
    ensure_tool "dig" "bind-utils"
else
    ensure_tool "dig" "dnsutils"
fi
ensure_tool "realpath" "coreutils"
ensure_tool "openssl" "openssl"
ensure_tool "qrencode" "qrencode" # For QR code generation
ensure_tool "crontab" "cron" # Ensure crontab command exists (package name varies)
ensure_tool "iptables" "iptables"
ensure_tool "ip6tables" "iptables"
ensure_tool "iptables-save" "iptables" # Needed for saving rules fallback
ensure_tool "ip6tables-save" "iptables"
ensure_tool "netfilter-persistent" "iptables-persistent" # Often needs manual setup like `dpkg-reconfigure iptables-persistent` on Debian/Ubuntu first time


realip(){
    ip=$(curl -s4m8 ip.sb -k)
    if [[ -z "$ip" ]]; then
        ip=$(curl -s6m8 ip.sb -k)
    fi
}

apply_cert_permissions() {
    local key_file_path="$1"
    local cert_file_path="$2"

    red "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    red "警告：您要求为私钥 '$key_file_path' (以及证书) 设置 777 (rwxrwxrwx) 权限。"
    red "这会带来严重的安全风险，因为它允许系统上任何用户读取、修改甚至删除您的私钥和证书。"
    red "强烈建议您在脚本执行完毕后，为私钥 '$key_file_path' 设置更严格的权限 (例如：chmod 600 '$key_file_path')。"
    red "证书 '$cert_file_path' 的权限建议为 644 (例如：chmod 644 '$cert_file_path')。"
    red "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    yellow "按任意键继续并应用 777 权限，或按 Ctrl+C 中止脚本..."
    read -n 1 -s # Wait for a single key press, silent

    chmod 777 "$key_file_path"
    chmod 777 "$cert_file_path"
    green "权限已按要求设置为 777: '$key_file_path', '$cert_file_path'"
}


inst_cert(){
    green "Hysteria 2 协议证书申请方式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 必应自签证书 ${YELLOW}（默认）${PLAIN} -> ${RED}客户端 insecure 必须为 true${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Acme 脚本自动申请 -> ${GREEN}客户端 insecure 可以为 false${PLAIN}"
    echo -e " ${GREEN}3.${PLAIN} 自定义证书路径 (将复制到 /etc/hysteria/) -> ${GREEN}客户端 insecure 可以为 false (证书需客户端信任)${PLAIN}"
    echo ""
    read -rp "请输入选项 [1-3]: " certInput

    USE_INSECURE_CLIENT_CONFIG="true"

    local target_cert_dir="/etc/hysteria"
    # These will be the final paths for Hysteria config, update global cert_path & key_path
    cert_path="$target_cert_dir/cert.crt"
    key_path="$target_cert_dir/private.key"
    local ca_log_path="$target_cert_dir/ca.log" # ACME log also in target dir

    mkdir -p "$target_cert_dir" # Ensure directory exists for all cert types

    if [[ $certInput == 2 ]]; then
        chmod a+x "$HOME" # Ensure acme.sh install dir is accessible

        if [[ -f "$cert_path" && -f "$key_path" ]] && [[ -s "$cert_path" && -s "$key_path" ]] && [[ -f "$ca_log_path" ]]; then
            domain=$(cat "$ca_log_path")
            green "检测到原有域名 '$domain' 的ACME证书 ($cert_path, $key_path)，将直接应用。"
            hy_domain="$domain"
            USE_INSECURE_CLIENT_CONFIG="false"
            apply_cert_permissions "$key_path" "$cert_path" # Apply user-requested permissions
            if [[ -z "$ip" ]]; then red "错误: 服务器IP未设置。"; exit 1; fi
            yellow "将使用服务器IP: $ip, SNI: $hy_domain 生成客户端配置 (insecure: $USE_INSECURE_CLIENT_CONFIG)。"
        else
            green "准备为新域名申请ACME证书 (将保存到 $target_cert_dir)..."
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            local temp_server_ipv4=""
            local temp_server_ipv6=""

            yellow "正在检测服务器公网IP地址..."
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                green "检测到WARP已激活，临时停用WARP以获取真实IP..."
                wg-quick down wgcf >/dev/null 2>&1; systemctl stop warp-go >/dev/null 2>&1; sleep 3
                temp_server_ipv4=$(curl -s4m8 ip.sb -k); temp_server_ipv6=$(curl -s6m8 ip.sb -k)
                green "尝试重新激活WARP...";
                if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                    wg-quick up wgcf >/dev/null 2>&1; systemctl start warp-go >/dev/null 2>&1
                fi
            else
                temp_server_ipv4=$(curl -s4m8 ip.sb -k); temp_server_ipv6=$(curl -s6m8 ip.sb -k)
            fi

            if [[ -z "$temp_server_ipv4" && -z "$temp_server_ipv6" ]]; then red "错误：无法获取服务器公网IP！"; exit 1; fi
            yellow "检测到服务器公网IPs: IPv4: ${temp_server_ipv4:-N/A}, IPv6: ${temp_server_ipv6:-N/A}"

            read -p "请输入需要申请证书的域名：" domain_input_for_acme
            [[ -z "$domain_input_for_acme" ]] && red "未输入域名！" && exit 1
            domain="$domain_input_for_acme"; green "已输入的域名：$domain" && sleep 1

            yellow "正在解析域名 '$domain' 的DNS记录..."
            local domain_a_record_ip=$(dig A +short "$domain" | head -n1)
            local domain_aaaa_record_ip=$(dig AAAA +short "$domain" | head -n1)
            local is_ipv6_validation_for_acme=false

            if [[ -n "$temp_server_ipv4" && -n "$domain_a_record_ip" && "$domain_a_record_ip" == "$temp_server_ipv4" ]]; then
                ip="$temp_server_ipv4"; is_ipv6_validation_for_acme=false
                green "验证成功: 域名 '$domain' A记录 ($domain_a_record_ip) -> 服务器 IPv4 ($ip)."
            elif [[ -n "$temp_server_ipv6" && -n "$domain_aaaa_record_ip" && "$domain_aaaa_record_ip" == "$temp_server_ipv6" ]]; then
                ip="$temp_server_ipv6"; is_ipv6_validation_for_acme=true
                green "验证成功: 域名 '$domain' AAAA记录 ($domain_aaaa_record_ip) -> 服务器 IPv6 ($ip)."
            else
                red "错误：域名DNS记录与服务器IP不匹配或无法解析。"; yellow "详情: SrvIP4:${temp_server_ipv4:-无} SrvIP6:${temp_server_ipv6:-无} DomA:${domain_a_record_ip:-无} DomAAAA:${domain_aaaa_record_ip:-无}"; exit 1
            fi

            # Ensure cron/cronie and other dependencies are installed
            local acme_deps=("curl" "wget" "sudo" "socat" "openssl")
             if [[ "$SYSTEM" == "CentOS" || "$SYSTEM" == "Fedora" || "$SYSTEM" == "Rocky" || "$SYSTEM" == "Alma" ]]; then
                 acme_deps+=("cronie")
            else
                 acme_deps+=("cron")
            fi
            for dep_pkg in "${acme_deps[@]}"; do
                 ${PACKAGE_INSTALL[int]} "$dep_pkg"
            done
            # Start and enable cron service
            local cron_daemon_to_manage="cron"
            if [[ "$SYSTEM" == "CentOS" || "$SYSTEM" == "Fedora" || "$SYSTEM" == "Rocky" || "$SYSTEM" == "Alma" ]]; then
                cron_daemon_to_manage="crond"
            fi
            systemctl start "$cron_daemon_to_manage" 2>/dev/null ; systemctl enable "$cron_daemon_to_manage" 2>/dev/null

            local ACME_SH_PATH="$HOME/.acme.sh/acme.sh"
            if [[ ! -f "$ACME_SH_PATH" ]]; then
                yellow "$ACME_SH_PATH 未找到。安装acme.sh..."; mkdir -p "$HOME/.acme.sh"
                if curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com; then green "acme.sh 安装成功。"; else red "acme.sh 安装失败。"; exit 1; fi
                if [[ -f "$HOME/.bashrc" ]]; then source "$HOME/.bashrc"; fi
            fi
            if [[ ! -f "$ACME_SH_PATH" ]]; then red "$ACME_SH_PATH 文件不存在。"; exit 1; fi
            if [[ ! -x "$ACME_SH_PATH" ]]; then yellow "$ACME_SH_PATH 不可执行。尝试chmod +x..."; chmod +x "$ACME_SH_PATH"; if [[ ! -x "$ACME_SH_PATH" ]]; then red "未能使 $ACME_SH_PATH 可执行。"; exit 1; fi; fi

            "$ACME_SH_PATH" --upgrade --auto-upgrade
            "$ACME_SH_PATH" --set-default-ca --server letsencrypt

            green "为 '$domain' 申请证书 (使用 ${ip})..."
            local issue_cmd_status
            if $is_ipv6_validation_for_acme; then "$ACME_SH_PATH" --issue -d "${domain}" --standalone -k ec-256 --insecure --listen-v6; issue_cmd_status=$?;
            else "$ACME_SH_PATH" --issue -d "${domain}" --standalone -k ec-256 --insecure; issue_cmd_status=$?; fi
            if [[ $issue_cmd_status -ne 0 ]]; then red "acme.sh --issue 失败，码: $issue_cmd_status。"; exit 1; fi
            green "证书签发命令为 '$domain' 执行完毕。"

            green "安装 '$domain' 的证书到 $target_cert_dir ..."
            if "$ACME_SH_PATH" --install-cert -d "${domain}" --key-file "$key_path" --fullchain-file "$cert_path" --ecc; then
                if [[ -f "$cert_path" && -f "$key_path" ]] && [[ -s "$cert_path" && -s "$key_path" ]]; then
                    echo "$domain" > "$ca_log_path"

                    # CRON JOB SETUP (Robust version)
                    green "正在尝试设置acme.sh证书自动续签的cron任务..."
                    local cron_service_active=false
                    local cron_daemon_name="cron"
                    if [[ "$SYSTEM" == "CentOS" || "$SYSTEM" == "Fedora" || "$SYSTEM" == "Rocky" || "$SYSTEM" == "Alma" ]]; then
                        cron_daemon_name="crond"
                    fi

                    if systemctl is-active --quiet "$cron_daemon_name"; then
                        green "Cron服务 ($cron_daemon_name) 正在运行。"
                        cron_service_active=true
                    else
                        yellow "警告: Cron服务 ($cron_daemon_name) 当前未运行。正在尝试启动..."
                        systemctl start "$cron_daemon_name"
                        sleep 2
                        if systemctl is-active --quiet "$cron_daemon_name"; then
                            green "Cron服务 ($cron_daemon_name) 已成功启动。"
                            cron_service_active=true
                        else
                            red "错误: 无法启动Cron服务 ($cron_daemon_name)。自动续签将无法工作。"
                        fi
                    fi

                    local cron_job_set_successfully=false
                    if $cron_service_active; then
                        local current_crontab_content
                        current_crontab_content=$(crontab -l 2>/dev/null)
                        local acme_cron_cmd
                        acme_cron_cmd=$(printf "0 0 * * * %s --cron -f >/dev/null 2>&1" "\"$ACME_SH_PATH\"")

                        local new_crontab_content
                        new_crontab_content=$(echo -e "${current_crontab_content}" | grep -vF "\"$ACME_SH_PATH\" --cron")
                        new_crontab_content=$(echo -e "${new_crontab_content}\n${acme_cron_cmd}" | sed '/^$/d')

                        if echo "${new_crontab_content}" | crontab -; then
                            green "用户crontab更新成功 (尝试)。"
                        else
                            yellow "警告: 更新用户crontab失败。将尝试 /etc/crontab (如果适用)。"
                        fi

                        if [[ -w /etc/crontab && ("$SYSTEM" == "CentOS" || "$SYSTEM" == "Fedora" || "$SYSTEM" == "Rocky" || "$SYSTEM" == "Alma") ]]; then
                            green "正在检查/更新 /etc/crontab (适用于 $SYSTEM)..."
                            local cron_pattern_in_etc_crontab
                            cron_pattern_in_etc_crontab=$(printf '%s\n' "\"$ACME_SH_PATH\" --cron" | sed 's/[\/\.*^$[]/\\&/g')

                            sudo sed -i "/${cron_pattern_in_etc_crontab}/d" /etc/crontab
                            echo "0 0 * * * root \"$ACME_SH_PATH\" --cron -f >/dev/null 2>&1" | sudo tee -a /etc/crontab >/dev/null
                            green "/etc/crontab 已尝试更新。"
                        fi

                        sleep 1

                        if crontab -l 2>/dev/null | grep -qF "\"$ACME_SH_PATH\" --cron" || grep -qF "\"$ACME_SH_PATH\" --cron" /etc/crontab 2>/dev/null ; then
                             green "acme.sh 证书自动续签的cron任务已成功设置/验证。"
                             cron_job_set_successfully=true
                        fi
                    fi

                    if ! $cron_job_set_successfully; then
                         yellow "警告: 未能自动设置acme.sh的cron续签任务。您可能需要手动设置。"
                         yellow "请尝试手动添加以下行到root用户的crontab或/etc/crontab:"
                         yellow "0 0 * * * \"$ACME_SH_PATH\" --cron -f >/dev/null 2>&1"
                    fi
                    # END CRON JOB SETUP

                    apply_cert_permissions "$key_path" "$cert_path"

                    green "证书申请与安装成功!"; yellow "证书: $cert_path, 私钥: $key_path"
                    hy_domain="$domain"
                    USE_INSECURE_CLIENT_CONFIG="false"
                else red "证书文件 ($cert_path, $key_path) 未生成或为空。"; exit 1; fi
            else red "acme.sh --install-cert 失败。"; exit 1; fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -p "请输入您现有公钥文件crt的【绝对路径】：" cert_path_input
        local verified_source_cert_path
        if ! verified_source_cert_path=$(realpath -e "$cert_path_input" 2>/dev/null); then red "公钥路径 '$cert_path_input' 无效或文件不存在。"; exit 1; fi

        read -p "请输入您现有密钥文件key的【绝对路径】：" key_path_input
        local verified_source_key_path
        if ! verified_source_key_path=$(realpath -e "$key_path_input" 2>/dev/null); then red "密钥路径 '$key_path_input' 无效或文件不存在。"; exit 1; fi

        green "正在复制自定义证书到 $target_cert_dir ..."
        # Global cert_path & key_path are already set to $target_cert_dir/...
        if cp "$verified_source_cert_path" "$cert_path" && cp "$verified_source_key_path" "$key_path"; then
            green "自定义证书已复制到 $cert_path 和 $key_path"
            apply_cert_permissions "$key_path" "$cert_path"
        else
            red "错误：复制自定义证书失败。"
            exit 1
        fi

        read -p "请输入证书对应的域名 (SNI)：" domain_input_custom
        [[ -z "$domain_input_custom" ]] && red "SNI域名不能为空!" && exit 1
        domain="$domain_input_custom"; hy_domain="$domain_input_custom"
        yellow "证书SNI将使用：$hy_domain"
        yellow "警告: 使用自定义证书时，为确保客户端 'insecure: false' 能正常工作，此证书必须由客户端信任的CA签发。"
        USE_INSECURE_CLIENT_CONFIG="false"
        if [[ -z "$ip" ]]; then red "错误: 服务器IP未设置。"; exit 1; fi
    else
        green "将使用必应自签证书 (客户端 insecure 必须为 true)"
        # Global cert_path/key_path are already set to $target_cert_dir/...
        openssl ecparam -genkey -name prime256v1 -out "$key_path"
        openssl req -new -x509 -days 36500 -key "$key_path" -out "$cert_path" -subj "/CN=www.bing.com"

        apply_cert_permissions "$key_path" "$cert_path"

        domain="www.bing.com"; hy_domain="www.bing.com"
        yellow "自签证书SNI将使用：$hy_domain"
        yellow "注意: 使用自签名证书，客户端必须配置为 'insecure: true' 才能连接。"
        USE_INSECURE_CLIENT_CONFIG="true"
        if [[ -z "$ip" ]]; then red "错误: 服务器IP未设置。"; exit 1; fi
    fi
}

inst_port(){
    read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port_input
    [[ -z "$port_input" ]] && port_input=$(shuf -i 2000-65535 -n 1)
    port="$port_input"
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port_input
            [[ -z "$port_input" ]] && port_input=$(shuf -i 2000-65535 -n 1)
            port="$port_input"
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

    # Clear previous jump rules by this script
    while IFS= read -r rule_line_args; do
      [[ -n "$rule_line_args" ]] && iptables -t nat -D $rule_line_args
    done < <(iptables-save -t nat | grep -oP "PREROUTING .* --comment \"$PORT_JUMP_COMMENT\"" || true)
    while IFS= read -r rule_line_args; do
      [[ -n "$rule_line_args" ]] && ip6tables -t nat -D $rule_line_args
    done < <(ip6tables-save -t nat | grep -oP "PREROUTING .* --comment \"$PORT_JUMP_COMMENT\"" || true)

    if [[ $jumpInput == 2 ]]; then
        read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport_input
        read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport_input

        if ! [[ "$firstport_input" =~ ^[0-9]+$ && "$firstport_input" -ge 1 && "$firstport_input" -le 65535 ]] || \
           ! [[ "$endport_input" =~ ^[0-9]+$ && "$endport_input" -ge 1 && "$endport_input" -le 65535 ]]; then
            red "错误：起始端口和末尾端口必须是1-65535之间的数字。"; firstport=""; endport="";
        elif [[ "$firstport_input" -ge "$endport_input" ]]; then
            red "错误：起始端口必须小于末尾端口。"; firstport=""; endport="";
        else
            firstport="$firstport_input"; endport="$endport_input"
        fi

        if [[ -n "$firstport" && -n "$endport" ]]; then
            yellow "设置端口跳跃: $firstport:$endport -> $port"
            iptables -t nat -A PREROUTING -p udp --dport "$firstport:$endport" -j DNAT --to-destination ":$port" -m comment --comment "$PORT_JUMP_COMMENT"
            ip6tables -t nat -A PREROUTING -p udp --dport "$firstport:$endport" -j DNAT --to-destination ":$port" -m comment --comment "$PORT_JUMP_COMMENT"

            if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1
            elif command -v iptables-save >/dev/null 2>&1 && command -v ip6tables-save >/dev/null 2>&1; then
                 mkdir -p /etc/iptables; iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6
                 green "iptables规则已尝试保存到 /etc/iptables/"
            else yellow "警告: 未找到netfilter-persistent或iptables-save，防火墙规则可能在重启后丢失。"; fi
        else red "端口跳跃设置无效或已跳过。"; unset firstport; unset endport; fi
    else red "将继续使用单端口模式"; unset firstport; unset endport; fi
}

inst_pwd(){
    read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" pwd_input
    [[ -z "$pwd_input" ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8) || auth_pwd="$pwd_input"
    yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
}

inst_site(){
    read -rp "请输入 Hysteria 2 的伪装网站地址 （去除https://） [默认 en.snu.ac.kr]：" site_input
    [[ -z "$site_input" ]] && proxysite="en.snu.ac.kr" || proxysite="$site_input"
    yellow "使用在 Hysteria 2 节点的伪装网站为：$proxysite"
}

insthysteria(){
    realip
    [[ -z "$ip" ]] && red "错误：无法获取服务器的公网IP地址！ Hysteria安装中止。" && exit 1
    yellow "脚本初步检测到服务器IP为: $ip (后续证书申请流程可能会根据DNS验证更新此IP)"

    local packages_to_install=("curl" "wget" "sudo" "qrencode" "procps" "iptables-persistent" "netfilter-persistent" "coreutils" "openssl")
    if [[ "$SYSTEM" == "CentOS" || "$SYSTEM" == "Fedora" || "$SYSTEM" == "Rocky" || "$SYSTEM" == "Alma" ]]; then
        packages_to_install+=("bind-utils" "cronie")
    else
        packages_to_install+=("dnsutils" "cron")
    fi

    if [[ ! "$SYSTEM" == "CentOS" && ! "$SYSTEM" == "Fedora" && ! "$SYSTEM" == "Rocky" && ! "$SYSTEM" == "Alma" ]]; then ${PACKAGE_UPDATE[int]}; fi
    for pkg_name_full in "${packages_to_install[@]}"; do
        local pkg_to_check="$pkg_name_full"; local package_name_for_os="$pkg_name_full"
        case "$pkg_name_full" in
             "bind-utils") [[ "$SYSTEM" == "CentOS" || "$SYSTEM" == "Fedora" || "$SYSTEM" == "Rocky" || "$SYSTEM" == "Alma" ]] && pkg_to_check="dig" || continue ;;
             "dnsutils") [[ ! "$SYSTEM" == "CentOS" && ! "$SYSTEM" == "Fedora" && ! "$SYSTEM" == "Rocky" && ! "$SYSTEM" == "Alma" ]] && pkg_to_check="dig" || continue ;;
             "coreutils") pkg_to_check="realpath" ;;
             "cronie") [[ "$SYSTEM" == "CentOS" || "$SYSTEM" == "Fedora" || "$SYSTEM" == "Rocky" || "$SYSTEM" == "Alma" ]] && pkg_to_check="crontab" || continue ;;
             "cron") [[ ! "$SYSTEM" == "CentOS" && ! "$SYSTEM" == "Fedora" && ! "$SYSTEM" == "Rocky" && ! "$SYSTEM" == "Alma" ]] && pkg_to_check="crontab" || continue ;;
             "iptables-persistent") package_name_for_os="iptables-persistent" ;; # Handle package name if different
             "netfilter-persistent") package_name_for_os="iptables-persistent" ;; # Often same package
             *) ;; # Default case
        esac
        ensure_tool "$pkg_to_check" "$package_name_for_os"
    done


    if [[ ! -f "/usr/local/bin/hysteria" ]]; then
        wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
        if [[ ! -f "install_server.sh" ]]; then red "错误：无法下载 Hysteria 2 安装脚本。"; exit 1; fi
        bash install_server.sh; rm -f install_server.sh
    else green "检测到 Hysteria 2 主程序已存在。"; fi

    if [[ -f "/usr/local/bin/hysteria" ]]; then green "Hysteria 2 主程序准备就绪！"; else red "Hysteria 2 主程序安装失败或未找到！"; exit 1; fi

    inst_cert
    inst_port
    inst_pwd
    inst_site

    [[ -z "$ip" ]] && red "内部错误: IP ($ip) 未设置。" && exit 1
    [[ -z "$port" ]] && red "内部错误: Port ($port) 未设置。" && exit 1
    [[ -z "$auth_pwd" ]] && red "内部错误: Password ($auth_pwd) 未设置。" && exit 1
    [[ -z "$hy_domain" ]] && red "内部错误: SNI ($hy_domain) 未设置。" && exit 1
    [[ ! -f "$cert_path" || ! -f "$key_path" ]] && red "内部错误: 证书或密钥在 $cert_path / $key_path 未找到。" && exit 1

    # $cert_path and $key_path are now always /etc/hysteria/... from inst_cert
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

    local client_tls_insecure_bool_value="true"
    local client_tls_insecure_int_value="1"
    if [[ "$USE_INSECURE_CLIENT_CONFIG" == "false" ]]; then
        client_tls_insecure_bool_value="false"; client_tls_insecure_int_value="0"
        green "客户端配置将使用 'insecure: false' (证书将被验证)。"
    else
        yellow "客户端配置将使用 'insecure: true' (证书将不被严格验证)。"
    fi

    local config_port_for_client="$port"
    if [[ -n "$firstport" && -n "$endport" && "$firstport" -lt "$endport" ]]; then
        config_port_for_client="$port,$firstport-$endport"
    fi
    local config_ip_for_client="$ip"
    if [[ "$ip" == *":"* ]]; then config_ip_for_client="[$ip]"; fi

    mkdir -p /root/hy
    cat << EOF > /root/hy/hy-client.yaml
server: $config_ip_for_client:$config_port_for_client
auth: $auth_pwd
tls:
  sni: $hy_domain
  insecure: $client_tls_insecure_bool_value
quic: {initStreamReceiveWindow: 16777216, maxStreamReceiveWindow: 16777216, initConnReceiveWindow: 33554432, maxConnReceiveWindow: 33554432}
fastOpen: true
socks5: {listen: 127.0.0.1:5678}
transport: {udp: {hopInterval: 30s}}
EOF
    local json_insecure_val="$client_tls_insecure_bool_value"
    if [[ "$json_insecure_val" != "true" && "$json_insecure_val" != "false" ]]; then json_insecure_val="true"; fi

    cat << EOF > /root/hy/hy-client.json
{
  "server": "$config_ip_for_client:$config_port_for_client",
  "auth": "$auth_pwd",
  "tls": { "sni": "$hy_domain", "insecure": $json_insecure_val },
  "quic": {"initStreamReceiveWindow": 16777216, "maxStreamReceiveWindow": 16777216, "initConnReceiveWindow": 33554432, "maxConnReceiveWindow": 33554432},
  "socks5": {"listen": "127.0.0.1:5678"},
  "transport": {"udp": {"hopInterval": "30s"}}
}
EOF

    local share_link_ip_formatted="$ip"
    if [[ "$ip" == *":"* ]]; then share_link_ip_formatted="[$ip]"; fi

    url="hysteria2://$auth_pwd@$share_link_ip_formatted:$config_port_for_client/?insecure=$client_tls_insecure_int_value&sni=$hy_domain#Hysteria2-$(echo $SYS | awk '{print $1}')-$(date +%m%d)"
    echo "$url" > /root/hy/url.txt

    systemctl daemon-reload
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then
        red "错误: 未找到Hysteria的systemd服务单元。请检查 install_server.sh。"; exit 1;
    fi

    systemctl enable "$SYSTEMD_SERVICE_NAME"; systemctl restart "$SYSTEMD_SERVICE_NAME"

    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 服务 ($SYSTEMD_SERVICE_NAME) 启动成功"
    else
        red "Hysteria 2 服务 ($SYSTEMD_SERVICE_NAME) 启动失败"; yellow "请运行 'systemctl status $SYSTEMD_SERVICE_NAME' 和 'journalctl -u $SYSTEMD_SERVICE_NAME -n 50 --no-pager' 查看日志。"; exit 1;
    fi
    red "======================================================================================"
    green "Hysteria 2 代理服务安装完成"
    showconf
    echo ""
    yellow "重要: 如果您使用了端口跳跃，请确保客户端支持该格式的端口定义 (port,start-end)。"
}

get_systemd_service_name(){
    if systemctl list-unit-files | grep -qw hysteria-server.service; then
        SYSTEMD_SERVICE_NAME="hysteria-server.service"
    elif systemctl list-unit-files | grep -qw hysteria.service; then
        SYSTEMD_SERVICE_NAME="hysteria.service"
    else
        SYSTEMD_SERVICE_NAME=""
    fi
}

unsthysteria(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then yellow "未检测到Hysteria服务单元。"; else
        systemctl stop "$SYSTEMD_SERVICE_NAME" >/dev/null 2>&1
        systemctl disable "$SYSTEMD_SERVICE_NAME" >/dev/null 2>&1
        rm -f "/lib/systemd/system/$SYSTEMD_SERVICE_NAME" "/usr/lib/systemd/system/$SYSTEMD_SERVICE_NAME"
        rm -f "/lib/systemd/system/hysteria-server@.service" "/usr/lib/systemd/system/hysteria-server@.service"
        systemctl daemon-reload
    fi

    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy

    local acme_cron_cmd_pattern="\"$HOME/.acme.sh/acme.sh\" --cron"
    if grep -qF "$acme_cron_cmd_pattern" /etc/crontab 2>/dev/null || crontab -l 2>/dev/null | grep -qF "$acme_cron_cmd_pattern"; then
        green "正在移除acme.sh的cron任务..."
        (crontab -l 2>/dev/null | grep -vF "$acme_cron_cmd_pattern") | crontab -
        if [[ -w /etc/crontab && ("$SYSTEM" == "CentOS" || "$SYSTEM" == "Fedora" || "$SYSTEM" == "Rocky" || "$SYSTEM" == "Alma") ]]; then
             local cron_pattern_escaped_for_sed
             cron_pattern_escaped_for_sed=$(printf '%s\n' "$acme_cron_cmd_pattern" | sed 's/[\/\.*^$[]/\\&/g')
             sed -i "/${cron_pattern_escaped_for_sed}/d" /etc/crontab
        fi
    fi

    green "正在移除由本脚本添加的iptables端口跳跃规则 (带注释 $PORT_JUMP_COMMENT)..."
    while IFS= read -r rule_to_delete_args; do
      [[ -n "$rule_to_delete_args" ]] && iptables -t nat -D ${rule_to_delete_args}
    done < <(iptables-save -t nat | grep -oP "PREROUTING .* --comment \"$PORT_JUMP_COMMENT\"" || true)
    while IFS= read -r rule_to_delete_args; do
      [[ -n "$rule_to_delete_args" ]] && ip6tables -t nat -D ${rule_to_delete_args}
    done < <(ip6tables-save -t nat | grep -oP "PREROUTING .* --comment \"$PORT_JUMP_COMMENT\"" || true)

    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1
    elif command -v iptables-save >/dev/null 2>&1 && command -v ip6tables-save >/dev/null 2>&1; then
         mkdir -p /etc/iptables; iptables-save > /etc/iptables/rules.v4; ip6tables-save > /etc/iptables/rules.v6
    fi

    read -rp "是否同时卸载acme.sh证书申请工具 (证书会保留在/etc/hysteria, 但acme工具本身移除)？[y/N]: " remove_acme
    if [[ "$remove_acme" =~ ^[Yy]$ ]]; then
        if command -v "$HOME/.acme.sh/acme.sh" &>/dev/null; then
            "$HOME/.acme.sh/acme.sh" --uninstall; rm -rf "$HOME/.acme.sh"; green "acme.sh已卸载。"
        else yellow "未找到acme.sh。"; fi
    fi
    green "Hysteria 2 已尝试彻底卸载完成！"
}

starthysteria(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务未找到!" && return; fi
    systemctl start "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then green "Hysteria 2 服务已启动。"; else
        red "Hysteria 2 服务启动失败。"; yellow "请运行 'systemctl status $SYSTEMD_SERVICE_NAME' 和 'journalctl -u $SYSTEMD_SERVICE_NAME -n 50 --no-pager' 查看日志。"; fi
}

stophysteria(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务未找到!" && return; fi
    systemctl stop "$SYSTEMD_SERVICE_NAME"; green "Hysteria 2 服务已停止。"
}

hysteriaswitch(){
    get_systemd_service_name
    if [[ -z "$SYSTEMD_SERVICE_NAME" && "$1" != "menu_return" ]]; then
        red "Hysteria 服务未安装或无法确定服务名。"
        read -n 1 -s -r -p "按任意键返回主菜单..." && menu && return
    fi
    echo ""; yellow "Hysteria 2 服务管理 (服务: ${SYSTEMD_SERVICE_NAME:-未找到}):"
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"; echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"; echo -e " ${GREEN}4.${PLAIN} 查看 Hysteria 2 状态"
    echo -e " ${GREEN}5.${PLAIN} 查看 Hysteria 2 日志"; echo -e " ${GREEN}0.${PLAIN} 返回主菜单"; echo ""
    read -rp "请输入选项 [0-5]: " switchInput
    case $switchInput in
        1) starthysteria ;; 2) stophysteria ;;
        3) if [[ -n "$SYSTEMD_SERVICE_NAME" ]]; then systemctl restart "$SYSTEMD_SERVICE_NAME"; green "Hysteria 2 服务已尝试重启。"; else red "服务名未知。"; fi ;;
        4) if [[ -n "$SYSTEMD_SERVICE_NAME" ]]; then systemctl status "$SYSTEMD_SERVICE_NAME"; else red "服务名未知。"; fi ;;
        5) if [[ -n "$SYSTEMD_SERVICE_NAME" ]]; then journalctl -u "$SYSTEMD_SERVICE_NAME" -n 50 --no-pager; else red "服务名未知。"; fi ;;
        0) menu ;; *) red "无效输入!" ; sleep 1 ;;
    esac
    [[ "$switchInput" != "0" ]] && read -n 1 -s -r -p "按任意键返回操作菜单..." && hysteriaswitch "menu_return"
}

update_client_configs_insecure_flag() {
    local bool_val="$1"
    local int_val="$2"

    if [[ -f /root/hy/hy-client.yaml ]]; then
        sed -i "s/insecure: \(true\|false\)/insecure: $bool_val/g" /root/hy/hy-client.yaml
    fi
    if [[ -f /root/hy/hy-client.json ]]; then
        local json_val_to_set="$bool_val"
        if [[ "$json_val_to_set" != "true" && "$json_val_to_set" != "false" ]]; then json_val_to_set="true"; fi
        sed -i "s/\"insecure\": \(true\|false\)/\"insecure\": $json_val_to_set/g" /root/hy/hy-client.json
    fi
    if [[ -f /root/hy/url.txt ]]; then
        sed -i "s/insecure=[01]/insecure=$int_val/g" /root/hy/url.txt
    fi
}

change_cert(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装。" && return; fi
    get_systemd_service_name; if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知!" && return; fi

    # Config always points to /etc/hysteria/... now, but read it for consistency check maybe?
    local old_cert_path_from_config=$(grep -oP 'cert: \K\S+' /etc/hysteria/config.yaml)
    local old_key_path_from_config=$(grep -oP 'key: \K\S+' /etc/hysteria/config.yaml)
    local old_hy_domain_client="N/A"; [[ -f /root/hy/hy-client.yaml ]] && old_hy_domain_client=$(grep -oP 'sni: \K\S+' /root/hy/hy-client.yaml || echo "N/A")

    local preserved_ip_before_cert_change="$ip"

    inst_cert # Updates globals: USE_INSECURE_CLIENT_CONFIG, cert_path, key_path, hy_domain, maybe ip. Sets perms.

    # Ensure config points to the standard paths (should already be if inst_cert worked)
    local std_cert_path="/etc/hysteria/cert.crt"; local std_key_path="/etc/hysteria/private.key"
    local esc_std_cert_path=$(printf '%s\n' "$std_cert_path" | sed 's:[][\/.^$*]:\\&:g')
    local esc_std_key_path=$(printf '%s\n' "$std_key_path" | sed 's:[][\/.^$*]:\\&:g')
    local esc_old_cert_path=$(printf '%s\n' "$old_cert_path_from_config" | sed 's:[][\/.^$*]:\\&:g')
    local esc_old_key_path=$(printf '%s\n' "$old_key_path_from_config" | sed 's:[][\/.^$*]:\\&:g')
    sed -i "s|cert: $esc_old_cert_path|cert: $esc_std_cert_path|g" /etc/hysteria/config.yaml
    sed -i "s|key: $esc_old_key_path|key: $esc_std_key_path|g" /etc/hysteria/config.yaml

    local escaped_old_sni=$(printf '%s\n' "$old_hy_domain_client" | sed 's:[][\/.^$*]:\\&:g')
    local escaped_new_sni=$(printf '%s\n' "$hy_domain" | sed 's:[][\/.^$*]:\\&:g')
    if [[ -f /root/hy/hy-client.yaml ]]; then sed -i "s/sni: $escaped_old_sni/sni: $escaped_new_sni/g" /root/hy/hy-client.yaml; fi
    if [[ -f /root/hy/hy-client.json ]]; then sed -i "s/\"sni\": \"$escaped_old_sni\"/\"sni\": \"$escaped_new_sni\"/g" /root/hy/hy-client.json; fi
    if [[ -f /root/hy/url.txt ]]; then sed -i "s/sni=$escaped_old_sni/sni=$escaped_new_sni/g" /root/hy/url.txt; fi

    if [[ "$ip" != "$preserved_ip_before_cert_change" && -n "$preserved_ip_before_cert_change" ]]; then
        yellow "服务器IP因ACME验证已更新为: $ip。更新客户端配置中的服务器地址..."
        local old_client_ip_f="$preserved_ip_before_cert_change"; if [[ "$preserved_ip_before_cert_change" == *":"* ]]; then old_client_ip_f="[$preserved_ip_before_cert_change]"; fi
        local new_client_ip_f="$ip"; if [[ "$ip" == *":"* ]]; then new_client_ip_f="[$ip]"; fi
        local esc_old_client_ip_f=$(printf '%s\n' "$old_client_ip_f" | sed 's:[][\/.^$*]:\\&:g')
        local esc_new_client_ip_f=$(printf '%s\n' "$new_client_ip_f" | sed 's:[][\/.^$*]:\\&:g')
        if [[ -f /root/hy/hy-client.yaml ]]; then sed -i "s|server: $esc_old_client_ip_f:|server: $esc_new_client_ip_f:|g" /root/hy/hy-client.yaml; fi
        if [[ -f /root/hy/hy-client.json ]]; then sed -i "s|\"server\": \"$esc_old_client_ip_f:|\"server\": \"$esc_new_client_ip_f:|g" /root/hy/hy-client.json; fi
        local escaped_old_ip_url_at="@$(printf '%s\n' "$old_client_ip_f" | sed 's:[][\/.^$*]:\\&:g')" # Simplified for clarity
        local escaped_new_ip_url_at="@$(printf '%s\n' "$new_client_ip_f" | sed 's:[][\/.^$*]:\\&:g')"
        if [[ -f /root/hy/url.txt ]]; then sed -i "s|$escaped_old_ip_url_at|$escaped_new_ip_url_at|g" /root/hy/url.txt; fi
    fi

    local bool_val_change="true"; local int_val_change="1"
    if [[ "$USE_INSECURE_CLIENT_CONFIG" == "false" ]]; then bool_val_change="false"; int_val_change="0"; fi
    update_client_configs_insecure_flag "$bool_val_change" "$int_val_change"

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 节点证书信息已成功修改。"; showconf
    else red "Hysteria 2 服务重启失败。"; fi
}

changeport(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装。" && return; fi
    get_systemd_service_name; if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知!" && return; fi

    local old_server_port=$(grep -oP 'listen: : *\K[0-9]+' /etc/hysteria/config.yaml 2>/dev/null)
    [[ -z "$old_server_port" ]] && red "无法读取旧端口。" && return 1

    read -p "当前监听端口: $old_server_port. 新端口[1-65535] (回车随机)：" new_port_input
    local new_port="${new_port_input:-$(shuf -i 2000-65535 -n 1)}"

    if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$new_port") && "$new_port" != "$old_server_port" ]]; then
        red "$new_port 端口已被占用！"; return 1;
    fi

    sed -i "s/listen: :$old_server_port/listen: :$new_port/g" /etc/hysteria/config.yaml

    if [[ -z "$ip" ]]; then realip; fi
    [[ -z "$ip" ]] && red "无法获取IP更新客户端配置。" && return 1

    local client_ip_f="$ip"; if [[ "$ip" == *":"* ]]; then client_ip_f="[$ip]"; fi
    local esc_client_ip_f=$(printf '%s\n' "$client_ip_f" | sed 's:[][\/.^$*]:\\&:g')

    # Update main port number in client config files and URL
    if [[ -f /root/hy/hy-client.yaml ]]; then sed -i "s/\(server: $esc_client_ip_f\):$old_server_port/\1:$new_port/" /root/hy/hy-client.yaml; fi
    if [[ -f /root/hy/hy-client.json ]]; then sed -i "s/\(\"server\": \"$esc_client_ip_f\):$old_server_port/\1:$new_port/" /root/hy/hy-client.json; fi
    if [[ -f /root/hy/url.txt ]]; then
        local esc_at_client_ip_f="@$esc_client_ip_f"
        sed -i "s/\($esc_at_client_ip_f\):$old_server_port/\1:$new_port/" /root/hy/url.txt
    fi

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 监听端口已修改为：$new_port"; yellow "客户端配置中的主端口已尝试更新。端口跳跃范围需手动检查/重新配置。"
        showconf
    else red "Hysteria 2 服务重启失败。"; fi
}

changepasswd(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装。" && return; fi
    get_systemd_service_name; if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知!" && return; fi

    local oldpasswd=$(grep -oP 'password: \K\S+' /etc/hysteria/config.yaml 2>/dev/null)
    [[ -z "$oldpasswd" ]] && red "无法读取旧密码。" && return 1

    read -p "当前密码: $oldpasswd. 新密码 (回车随机)：" new_passwd_input
    local new_passwd="${new_passwd_input:-$(date +%s%N | md5sum | cut -c 1-8)}"

    sed -i "s/password: $oldpasswd/password: $new_passwd/g" /etc/hysteria/config.yaml
    if [[ -f /root/hy/hy-client.yaml ]]; then sed -i "s/auth: $oldpasswd/auth: $new_passwd/g" /root/hy/hy-client.yaml; fi
    if [[ -f /root/hy/hy-client.json ]]; then sed -i "s/\"auth\": \"$oldpasswd\"/\"auth\": \"$new_passwd\"/g" /root/hy/hy-client.json; fi

    if [[ -f /root/hy/url.txt ]]; then
        local escaped_old_auth_url="hysteria2:\/\/$(printf '%s\n' "$oldpasswd" | sed 's:[][\/.^$*]:\\&:g')@"
        local new_auth_url="hysteria2://$new_passwd@"
        sed -i "s#$escaped_old_auth_url#$new_auth_url#g" /root/hy/url.txt
    fi

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 密码已修改为：$new_passwd"; showconf
    else red "Hysteria 2 服务重启失败。"; fi
}


changeproxysite(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 未安装。" && return; fi
    get_systemd_service_name; if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then red "Hysteria服务名未知!" && return; fi

    local oldproxysite=$(grep -oP 'url: https://\K\S+' /etc/hysteria/config.yaml)
    [[ -z "$oldproxysite" ]] && red "无法读取旧伪装网站。" && return 1

    inst_site # Sets global $proxysite

    local esc_old=$(printf '%s\n' "$oldproxysite" | sed 's:[][\/.^$*]:\\&:g')
    local esc_new=$(printf '%s\n' "$proxysite" | sed 's:[][\/.^$*]:\\&:g')
    sed -i "s|url: https://$esc_old|url: https://$esc_new|g" /etc/hysteria/config.yaml

    systemctl restart "$SYSTEMD_SERVICE_NAME"
    if [[ -n $(systemctl status "$SYSTEMD_SERVICE_NAME" 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 伪装网站已修改为：$proxysite"
    else red "Hysteria 2 服务重启失败。"; fi
}

changeconf(){
    if [[ ! -f "/etc/hysteria/config.yaml" ]]; then
        red "Hysteria 2 未安装。"; read -n 1 -s -r -p "按任意键返回主菜单..." && menu && return
    fi
    echo ""; green "Hysteria 2 配置变更选择:"
    echo -e " ${GREEN}1.${PLAIN} 修改监听端口"; echo -e " ${GREEN}2.${PLAIN} 修改连接密码"
    echo -e " ${GREEN}3.${PLAIN} 修改证书"; echo -e " ${GREEN}4.${PLAIN} 修改伪装网站"
    echo -e " ${GREEN}0.${PLAIN} 返回主菜单"; echo ""
    read -p " 请选择操作 [0-4]：" confAnswer
    case $confAnswer in
        1) changeport ;; 2) changepasswd ;; 3) change_cert ;; 4) changeproxysite ;;
        0) menu ;; *) red "无效输入!"; sleep 1 ;;
    esac
    [[ "$confAnswer" != "0" ]] && read -n 1 -s -r -p "按任意键返回配置修改菜单..." && changeconf
}

showconf(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then red "Hysteria 2 未安装或配置文件不存在。" && return; fi
    get_systemd_service_name
    echo ""; green "--- Hysteria 2 服务器配置 (/etc/hysteria/config.yaml) (服务: ${SYSTEMD_SERVICE_NAME:-未知}) ---"
    cat /etc/hysteria/config.yaml
    echo ""; green "--------------------------------------------------------------------"
    if [[ -f /root/hy/hy-client.yaml ]]; then
        echo ""; yellow "客户端 YAML (/root/hy/hy-client.yaml):"; cat /root/hy/hy-client.yaml
    fi
    if [[ -f /root/hy/hy-client.json ]]; then
        echo ""; yellow "客户端 JSON (/root/hy/hy-client.json):"; cat /root/hy/hy-client.json
    fi
    if [[ -f /root/hy/url.txt ]]; then
        echo ""; yellow "分享链接 (/root/hy/url.txt):"; local current_url=$(cat /root/hy/url.txt); echo "$current_url"
        echo ""; yellow "二维码分享链接:"; qrencode -t ANSIUTF8 "$current_url"
    fi
}

menu() {
    clear
    echo "#############################################################"
    echo -e "#         ${GREEN}Hysteria 2 一键安装脚本 (增强版)${PLAIN}         #"
    echo -e "#       ${YELLOW}作者: Misaka, Gemini (改进版)${PLAIN}         #"
    echo "#############################################################"
    echo ""; echo -e " ${GREEN}1.${PLAIN} 安装 Hysteria 2"; echo -e " ${RED}2.${PLAIN} 卸载 Hysteria 2"
    echo " ------------------------------------------------------------"
    echo -e " ${GREEN}3.${PLAIN} Hysteria 2 服务管理"; echo -e " ${GREEN}4.${PLAIN} 修改 Hysteria 2 配置"
    echo -e " ${GREEN}5.${PLAIN} 显示配置文件和链接"; echo " ------------------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 退出脚本"; echo ""

    get_systemd_service_name
    if [[ -f "/etc/hysteria/config.yaml" && -n "$SYSTEMD_SERVICE_NAME" ]]; then
        local current_status=$(systemctl is-active "$SYSTEMD_SERVICE_NAME" 2>/dev/null)
        if [[ "$current_status" == "active" ]]; then green "Hysteria 2 状态: $current_status (运行中)"
        elif [[ "$current_status" == "inactive" || "$current_status" == "failed" ]]; then yellow "Hysteria 2 状态: $current_status"
        else yellow "Hysteria 2 状态: 未知 (is-active: '$current_status')"; fi

        local cp=$(grep -oP 'listen: : *\K[0-9]+' /etc/hysteria/config.yaml 2>/dev/null)
        local cs="N/A"; [[ -f /root/hy/hy-client.yaml ]] && cs=$(grep -oP 'sni: \K\S+' /root/hy/hy-client.yaml 2>/dev/null || echo N/A)
        yellow "监听端口: ${cp:-N/A}, SNI: ${cs:-N/A}"
    elif [[ -f "/etc/hysteria/config.yaml" ]]; then yellow "Hysteria配置文件存在但服务名未知。"; else yellow "Hysteria 2 似乎未安装。"; fi
    echo ""
    read -rp "请输入选项 [0-5]: " menuInput
    case $menuInput in
        1) insthysteria ;; 2) unsthysteria ;; 3) hysteriaswitch ;; 4) changeconf ;;
        5) showconf ;; 0) echo "退出脚本。" && exit 0 ;; *) red "无效输入!" && sleep 1 ;;
    esac
    [[ "$menuInput" != "0" ]] && read -n 1 -s -r -p "按任意键返回主菜单..." && menu
}

# --- Main execution ---
menu