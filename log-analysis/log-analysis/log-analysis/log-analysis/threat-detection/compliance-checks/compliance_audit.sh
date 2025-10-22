#!/bin/bash
# Compliance Auditor - Security Audit Script
# Checks Linux system security compliance
# Run with: sudo bash compliance_audit.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

# Helper functions
echo_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

echo_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASS_COUNT++))
}

echo_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAIL_COUNT++))
}

echo_warning() {
    echo -e "${YELLOW}⚠ WARNING${NC}: $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root!${NC}"
        echo "Run with: sudo bash compliance_audit.sh"
        exit 1
    fi
}

# Password Policy Checks
check_password_policy() {
    echo_header "PASSWORD POLICY CHECKS"
    
    if grep -q "^PASS_MAX_DAYS.*[0-9]" /etc/login.defs; then
        max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
        if [ "$max_days" -le 90 ]; then
            echo_pass "Password maximum age is set to $max_days days"
        else
            echo_fail "Password maximum age ($max_days) exceeds 90 days"
        fi
    else
        echo_fail "Password maximum age not configured"
    fi
    
    if grep -q "^PASS_MIN_DAYS.*[0-9]" /etc/login.defs; then
        echo_pass "Password minimum age is configured"
    else
        echo_fail "Password minimum age not configured"
    fi
}

# File Permission Checks
check_file_permissions() {
    echo_header "FILE PERMISSION CHECKS"
    
    if [ -f /etc/ssh/sshd_config ]; then
        perms=$(stat -c %a /etc/ssh/sshd_config)
        if [ "$perms" = "600" ]; then
            echo_pass "SSH config has correct permissions (600)"
        else
            echo_fail "SSH config permissions are $perms (should be 600)"
        fi
    else
        echo_fail "SSH config file not found"
    fi
    
    if [ -f /etc/shadow ]; then
        perms=$(stat -c %a /etc/shadow)
        if [ "$perms" = "640" ] || [ "$perms" = "000" ]; then
            echo_pass "Shadow file has restrictive permissions ($perms)"
        else
            echo_fail "Shadow file permissions are $perms"
        fi
    fi
}

# SSH Security Checks
check_ssh_security() {
    echo_header "SSH SECURITY CHECKS"
    
    if [ ! -f /etc/ssh/sshd_config ]; then
        echo_fail "SSH config file not found"
        return
    fi
    
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        echo_pass "SSH root login is disabled"
    else
        echo_fail "SSH root login is not disabled"
    fi
    
    if grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config; then
        echo_pass "SSH empty passwords are disabled"
    else
        echo_fail "SSH allows empty passwords"
    fi
}

# Firewall Checks
check_firewall() {
    echo_header "FIREWALL CHECKS"
    
    if command -v ufw &> /dev/null; then
        status=$(ufw status | grep -i active)
        if [ ! -z "$status" ]; then
            echo_pass "UFW firewall is installed and active"
        else
            echo_fail "UFW firewall is not active"
        fi
    else
        echo_warning "UFW firewall is not installed"
    fi
}

# User Account Checks
check_user_accounts() {
    echo_header "USER ACCOUNT CHECKS"
    
    empty_passwords=$(awk -F: '($2 == "") { print $1 }' /etc/shadow)
    if [ -z "$empty_passwords" ]; then
        echo_pass "No user accounts with empty passwords"
    else
        echo_fail "Found accounts with empty passwords: $empty_passwords"
    fi
}

# System Updates Check
check_system_updates() {
    echo_header "SYSTEM UPDATES CHECK"
    
    if command -v apt-get &> /dev/null; then
        updates=$(apt-get upgrade -s 2>/dev/null | grep -c "^Inst")
        if [ "$updates" -eq 0 ]; then
            echo_pass "System is fully updated"
        else
            echo_fail "There are $updates updates available"
        fi
    else
        echo_warning "Could not determine package manager"
    fi
}

# Logging Checks
check_logging() {
    echo_header "LOGGING CHECKS"
    
    if systemctl is-active --quiet rsyslog; then
        echo_pass "Rsyslog service is running"
    else
        echo_fail "Rsyslog service is not running"
    fi
}

# Generate Summary
generate_summary() {
    echo_header "COMPLIANCE AUDIT SUMMARY"
    
    total=$((PASS_COUNT + FAIL_COUNT))
    percentage=$((PASS_COUNT * 100 / total))
    
    echo -e "Timestamp: $(date)"
    echo -e "System: $(uname -n)"
    echo -e "${GREEN}Passed Checks: $PASS_COUNT${NC}"
    echo -e "${RED}Failed Checks: $FAIL_COUNT${NC}"
    echo -e "Total Checks: $total"
    echo -e "\nCompliance Score: ${percentage}%\n"
    
    if [ "$percentage" -ge 80 ]; then
        echo -e "${GREEN}✓ System is in good compliance status${NC}"
    elif [ "$percentage" -ge 60 ]; then
        echo -e "${YELLOW}⚠ System has moderate compliance issues${NC}"
    else
        echo -e "${RED}✗ System has significant compliance issues${NC}"
    fi
}

# Main
main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          LINUX SECURITY COMPLIANCE AUDIT TOOL               ║"
    echo "║                   CIS Benchmark Check                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_root
    check_password_policy
    check_file_permissions
    check_ssh_security
    check_firewall
    check_user_accounts
    check_system_updates
    check_logging
    generate_summary
}

main
