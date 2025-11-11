#!/bin/bash

# =============================================
# SSH安全审计增强版脚本
# 功能：全面检查系统安全状态并生成审计报告
# 作者：Hsay19
# =============================================

# 配置变量 - 修改为脚本运行目录
CURRENT_TIME=$(date +"%Y-%m-%d_%H-%M-%S")
HOSTNAME=$(hostname | cut -d'.' -f1)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_DIR="${SCRIPT_DIR}/${HOSTNAME}_ssh_audit_${CURRENT_TIME}"
REPORT_FILE="${AUDIT_DIR}/ssh_security_report_${CURRENT_TIME}.txt"
ARCHIVE_FILE="${SCRIPT_DIR}/${HOSTNAME}_ssh_audit_${CURRENT_TIME}.tar.gz"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 创建审计目录
mkdir -p $AUDIT_DIR

# 日志函数
log_to_file() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "${AUDIT_DIR}/audit_execution.log"
}

# 检查函数
check_command() {
    local cmd=$1
    local desc=$2
    local output_file=$3
    
    echo -e "${CYAN}[检查] ${desc}...${NC}" | tee -a $REPORT_FILE
    log_to_file "执行检查: $desc"
    
    eval $cmd >> $output_file 2>&1
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}[成功] ${desc}完成${NC}" | tee -a $REPORT_FILE
    else
        echo -e "${YELLOW}[警告] ${desc}执行异常${NC}" | tee -a $REPORT_FILE
    fi
}

# 初始化报告文件
init_report() {
    {
        echo "=============================================="
        echo "          SSH安全审计报告"
        echo "=============================================="
        echo "主机名    : $(hostname)"
        echo "审计时间  : $(date)"
        echo "脚本目录  : $SCRIPT_DIR"
        echo "审计目录  : $AUDIT_DIR"
        echo "报告文件  : $REPORT_FILE"
        echo "=============================================="
        echo ""
    } > $REPORT_FILE
}

# 1. 账户安全检查
check_account_security() {
    echo -e "\n${BLUE}============= 账户安全检查 =============${NC}" | tee -a $REPORT_FILE
    
    check_command "awk -F: '{if(\$3>=500 && \$3<65534 || \$3==0) print \"用户:\" \$1 \" UID:\" \$3 \" Shell:\" \$7}' /etc/passwd | grep -v \"^root\"" \
    "检查异常账户" "${AUDIT_DIR}/01_abnormal_accounts.txt"
    
    check_command "awk -F: '\$4==0 && \$1!=\"root\"{print \"用户:\" \$1 \" GID:\" \$4}' /etc/passwd" \
    "检查属组为0的非root账户" "${AUDIT_DIR}/02_gid0_accounts.txt"
    
    check_command "awk -F: '\$3==0{print \"特权用户:\" \$1 \" UID:\" \$3}' /etc/passwd" \
    "检查特权用户(UID为0)" "${AUDIT_DIR}/03_privileged_users.txt"
    
    check_command "awk -F: '(\$2!=\"*\" && \$2!=\"!!\"){print \"可登录用户:\" \$1}' /etc/shadow" \
    "检查可远程登录的账户" "${AUDIT_DIR}/04_login_users.txt"
    
    check_command "grep -v \"^#\\|^$\\|^root\" /etc/sudoers 2>/dev/null | grep \"ALL=(ALL)\"" \
    "检查有sudo权限的非root账户" "${AUDIT_DIR}/05_sudo_users.txt"
    
    check_command "awk -F: '\$7==\"/bin/false\" || \$7==\"/usr/sbin/nologin\" {print \"禁用登录用户:\" \$1}' /etc/passwd" \
    "检查禁用登录的用户" "${AUDIT_DIR}/06_disabled_users.txt"
}

# 2. 登录安全检查
check_login_security() {
    echo -e "\n${BLUE}============= 登录安全检查 =============${NC}" | tee -a $REPORT_FILE
    
    check_command "last -n 30" \
    "最近成功登录记录" "${AUDIT_DIR}/07_successful_logins.txt"
    
    check_command "if [ -f /var/log/btmp ]; then lastb | head -n 30; else echo '登录失败日志不存在'; fi" \
    "最近登录失败记录" "${AUDIT_DIR}/08_failed_logins.txt"
    
    check_command "grep -i \"accepted\\|failed\" /var/log/secure 2>/dev/null | tail -n 20 || grep -i \"accepted\\|failed\" /var/log/auth.log 2>/dev/null | tail -n 20" \
    "最近认证日志" "${AUDIT_DIR}/09_auth_logs.txt"
    
    check_command "who" \
    "当前登录用户" "${AUDIT_DIR}/10_current_users.txt"
}

# 3. SSH配置检查
check_ssh_config() {
    echo -e "\n${BLUE}============= SSH配置检查 =============${NC}" | tee -a $REPORT_FILE
    
    local sshd_config="/etc/ssh/sshd_config"
    if [ -f "$sshd_config" ]; then
        check_command "grep -E \"^PermitRootLogin|^PasswordAuthentication|^Protocol|^Port|^MaxAuthTries|^ClientAliveInterval\" $sshd_config" \
        "SSH关键配置" "${AUDIT_DIR}/11_ssh_config.txt"
        
        check_command "sshd -t 2>&1" \
        "SSH配置语法检查" "${AUDIT_DIR}/12_ssh_syntax_check.txt"
    else
        echo -e "${YELLOW}[警告] SSH配置文件不存在${NC}" | tee -a $REPORT_FILE
    fi
    
    check_command "ls -la /root/.ssh/ 2>/dev/null && cat /root/.ssh/authorized_keys 2>/dev/null" \
    "root用户SSH密钥" "${AUDIT_DIR}/13_root_ssh_keys.txt"
}

# 4. 网络连接检查
check_network_security() {
    echo -e "\n${BLUE}============= 网络连接检查 =============${NC}" | tee -a $REPORT_FILE
    
    check_command "netstat -antp | grep -E 'ESTABLISHED|LISTEN'" \
    "当前网络连接" "${AUDIT_DIR}/14_network_connections.txt"
    
    check_command "netstat -tulnp" \
    "当前开放端口" "${AUDIT_DIR}/15_listening_ports.txt"
    
    check_command "ss -tulnp" \
    "使用ss命令检查端口" "${AUDIT_DIR}/16_ss_ports.txt"
    
    check_command "lsof -i -P -n | head -n 50" \
    "网络连接详细信息" "${AUDIT_DIR}/17_lsof_network.txt"
}

# 5. 进程检查
check_process_security() {
    echo -e "\n${BLUE}============= 进程检查 =============${NC}" | tee -a $REPORT_FILE
    
    check_command "ps aux --sort=-pcpu | head -n 15" \
    "高CPU使用进程" "${AUDIT_DIR}/18_high_cpu_processes.txt"
    
    check_command "ps aux --sort=-pmem | head -n 15" \
    "高内存使用进程" "${AUDIT_DIR}/19_high_memory_processes.txt"
    
    check_command "ps -eo pid,user,comm,etime --sort=etime | grep -E ' ([0-9]+-)?[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -n 20" \
    "长时间运行进程" "${AUDIT_DIR}/20_long_running_processes.txt"
    
    check_command "ps aux | grep -E '[s]shd'" \
    "SSH相关进程" "${AUDIT_DIR}/21_ssh_processes.txt"
}

# 6. 计划任务检查
check_cron_security() {
    echo -e "\n${BLUE}============= 计划任务检查 =============${NC}" | tee -a $REPORT_FILE
    
    check_command "cat /etc/crontab | grep -v \"^#\"" \
    "系统cron任务" "${AUDIT_DIR}/22_system_cron.txt"
    
    check_command "for user in \$(cut -f1 -d: /etc/passwd); do echo \"=== User: \$user ===\"; crontab -l -u \$user 2>/dev/null; done" \
    "用户cron任务" "${AUDIT_DIR}/23_user_cron.txt"
    
    check_command "ls -la /etc/cron.d/ && echo '--- 文件内容 ---' && for file in /etc/cron.d/*; do echo \"文件: \$file\"; cat \$file; done 2>/dev/null" \
    "/etc/cron.d目录内容" "${AUDIT_DIR}/24_cron_d_contents.txt"
    
    check_command "ls -la /var/spool/cron/ 2>/dev/null" \
    "用户cron文件" "${AUDIT_DIR}/25_spool_cron.txt"
}

# 7. 启动项检查
check_startup_security() {
    echo -e "\n${BLUE}============= 启动项检查 =============${NC}" | tee -a $REPORT_FILE
    
    check_command "ls -la /etc/init.d/ | head -n 20" \
    "/etc/init.d目录内容" "${AUDIT_DIR}/26_init_d_contents.txt"
    
    check_command "cat /etc/rc.local | grep -v \"^#\" 2>/dev/null || echo 'rc.local文件不存在'" \
    "/etc/rc.local内容" "${AUDIT_DIR}/27_rc_local.txt"
    
    if command -v systemctl >/dev/null; then
        check_command "systemctl list-unit-files | grep enabled" \
        "系统服务(enabled)" "${AUDIT_DIR}/28_systemd_services.txt"
    else
        check_command "chkconfig --list | grep ':on'" \
        "系统服务(启用)" "${AUDIT_DIR}/28_chkconfig_services.txt"
    fi
}

# 8. 文件权限检查
check_file_permissions() {
    echo -e "\n${BLUE}============= 文件权限检查 =============${NC}" | tee -a $REPORT_FILE
    
    local critical_files=(
        "/etc/passwd" "/etc/shadow" "/etc/group" "/etc/sudoers"
        "/etc/ssh/sshd_config" "/etc/crontab" "/etc/rc.local"
    )
    
    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            check_command "ls -la $file" \
            "文件权限: $file" "${AUDIT_DIR}/29_file_permissions.txt"
        fi
    done
    
    check_command "find /etc/ssh/ -name \"*key*\" -type f -ls 2>/dev/null" \
    "SSH密钥文件" "${AUDIT_DIR}/30_ssh_key_files.txt"
}

# 9. 生成安全评分
generate_security_score() {
    echo -e "\n${BLUE}============= 安全评分 =============${NC}" | tee -a $REPORT_FILE
    
    local score=100
    local warnings=0
    
    # 检查特权用户数量
    local privileged_count=$(awk -F: '$3==0' /etc/passwd | wc -l)
    if [ $privileged_count -gt 1 ]; then
        ((score-=10))
        ((warnings++))
        echo -e "${YELLOW}[警告] 发现多个特权用户${NC}" | tee -a $REPORT_FILE
    fi
    
    # 检查root是否允许SSH登录
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
        ((score-=15))
        ((warnings++))
        echo -e "${YELLOW}[警告] 允许root SSH登录${NC}" | tee -a $REPORT_FILE
    fi
    
    # 检查密码认证是否开启
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
        ((score-=10))
        ((warnings++))
        echo -e "${YELLOW}[警告] 允许密码认证${NC}" | tee -a $REPORT_FILE
    fi
    
    echo -e "\n${GREEN}安全评分: $score/100${NC}" | tee -a $REPORT_FILE
    echo -e "发现警告: $warnings 个" | tee -a $REPORT_FILE
}

# 10. 打包审计结果
package_audit_results() {
    echo -e "\n${BLUE}============= 打包审计结果 =============${NC}" | tee -a $REPORT_FILE
    
    # 创建文件列表
    ls -la $AUDIT_DIR/ > "${AUDIT_DIR}/file_list.txt"
    
    # 打包所有文件
    echo -e "${CYAN}正在打包审计结果...${NC}" | tee -a $REPORT_FILE
    if tar -czf $ARCHIVE_FILE -C $(dirname $AUDIT_DIR) $(basename $AUDIT_DIR) 2>/dev/null; then
        echo -e "${GREEN}审计结果已打包: $ARCHIVE_FILE${NC}" | tee -a $REPORT_FILE
        echo -e "文件大小: $(du -h $ARCHIVE_FILE | cut -f1)" | tee -a $REPORT_FILE
        
        # 显示打包文件信息
        echo -e "\n${CYAN}打包文件内容:${NC}" | tee -a $REPORT_FILE
        tar -tzf $ARCHIVE_FILE | head -10 | tee -a $REPORT_FILE
        if [ $(tar -tzf $ARCHIVE_FILE | wc -l) -gt 10 ]; then
            echo "... (更多文件)" | tee -a $REPORT_FILE
        fi
    else
        echo -e "${RED}打包失败${NC}" | tee -a $REPORT_FILE
    fi
}

# 11. 清理临时文件（可选）
cleanup_temp_files() {
    echo -e "\n${BLUE}============= 清理选项 =============${NC}" | tee -a $REPORT_FILE
    
    read -p "是否删除原始审计目录只保留压缩包? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if rm -rf $AUDIT_DIR; then
            echo -e "${GREEN}已清理原始目录: $AUDIT_DIR${NC}" | tee -a $REPORT_FILE
        else
            echo -e "${YELLOW}清理目录失败${NC}" | tee -a $REPORT_FILE
        fi
    else
        echo -e "${CYAN}保留原始目录: $AUDIT_DIR${NC}" | tee -a $REPORT_FILE
    fi
}

# 主函数
main() {
    echo -e "${PURPLE}开始SSH安全审计...${NC}"
    echo -e "${CYAN}脚本运行目录: $SCRIPT_DIR${NC}"
    log_to_file "开始SSH安全审计"
    log_to_file "脚本目录: $SCRIPT_DIR"
    
    # 初始化
    init_report
    
    # 执行各项检查
    check_account_security
    check_login_security
    check_ssh_config
    check_network_security
    check_process_security
    check_cron_security
    check_startup_security
    check_file_permissions
    
    # 生成评分和打包
    generate_security_score
    package_audit_results
    
    # 清理选项
    cleanup_temp_files
    
    echo -e "\n${PURPLE}============= 审计完成 =============${NC}"
    echo -e "${GREEN}审计报告: $REPORT_FILE${NC}"
    echo -e "${GREEN}打包文件: $ARCHIVE_FILE${NC}"
    echo -e "${GREEN}详细日志: ${AUDIT_DIR}/audit_execution.log${NC}"
    echo -e "${CYAN}所有文件都保存在: $SCRIPT_DIR${NC}"
    
    log_to_file "SSH安全审计完成"
}

# 权限检查
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}警告: 建议使用root权限运行以获得完整信息${NC}"
    read -p "是否继续? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# 执行主函数
main
