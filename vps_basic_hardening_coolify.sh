#!/bin/bash

##################################################################################
# This bash script is usefull to do a basic hardening of a new vps. This
# script is designed to prepare a server to be connected and managed by Coolify.
# 
# Author: OXIVRA
# Website: https://oxivra.com
# License: MIT
# 
##################################################################################

# Ensure script is run as root
if [ "$(id -u)" != "0" ]; then
echo "This script must be run as root" 1>&2
exit 1
fi

########################################
# Interactive prompts (admin user)
########################################

# Prompt for admin username (non-empty, with validation in a loop)
while true; do
  read -p "Enter admin username to create (e.g., thisismyexampleserveradmin): " ADMIN_USER
  if [ -n "$ADMIN_USER" ]; then
    # If ADMIN_USER is not empty, break the loop
    break
  else
    # Print an error message and prompt the user again
    echo "Error: Admin username cannot be empty. Please try again."
  fi
done

# Prompt for smtp server (non-empty, with validation in a loop)
while true; do
  read -p "SMTP Server (e.g., smtp.gmail.com): " SMTP_HOST
  if [ -n "$SMTP_HOST" ]; then
    # If SMTP_HOST is not empty, break the loop
    break
  else
    # Print an error message and prompt the user again
    echo "Error: SMTP server cannot be empty. Please try again."
  fi
done

# Prompt for smtp port (non-empty, with validation in a loop)
while true; do
  read -p "SMTP Port (e.g., 587): " SMTP_PORT
  if [ -n "$SMTP_PORT" ]; then
    # If SMTP_PORT is not empty, break the loop
    break
  else
    # Print an error message and prompt the user again
    echo "Error: SMTP port cannot be empty. Please try again."
  fi
done

# Prompt for smtp username (non-empty, with validation in a loop)
while true; do
  read -p "SMTP Username (e.g., you@example.com): " SMTP_USER
  if [ -n "$SMTP_USER" ]; then
    # If SMTP_USER is not empty, break the loop
    break
  else
    # Print an error message and prompt the user again
    echo "Error: SMTP user cannot be empty. Please try again."
  fi
done

# Prompt for smtp password (non-empty, with validation in a loop)
while true; do
  read -p "SMTP Password: " SMTP_PASS
  if [ -n "$SMTP_PASS" ]; then
    # If SMTP_PASS is not empty, break the loop
    break
  else
    # Print an error message and prompt the user again
    echo "Error: SMTP password cannot be empty. Please try again."
  fi
done

# Prompt for notification recipient email address (non-empty, with validation in a loop)
while true; do
  read -p "Email Address to receive notifications: " EMAIL_DEST
  if [ -n "$EMAIL_DEST" ]; then
    # If EMAIL_DEST is not empty, break the loop
    break
  else
    # Print an error message and prompt the user again
    echo "Error: Recipient email address cannot be empty. Please try again."
  fi
done

# Prompt for notification sender email address (non-empty, with validation in a loop)
while true; do
  read -p "Email Address to send FROM (usually same as username): " EMAIL_FROM
  if [ -n "$EMAIL_FROM" ]; then
    # If EMAIL_FROM is not empty, break the loop
    break
  else
    # Print an error message and prompt the user again
    echo "Error: Sending email address cannot be empty. Please try again."
  fi
done

# Prompt for Coolify public SSH key (non-empty, with validation in a loop)
while true; do
  read -p "Coolify Public SSH Key: " COOLIFY_KEY
  if [ -n "$COOLIFY_KEY" ]; then
    # If COOLIFY_KEY is not empty, break the loop
    break
  else
    # Print an error message and prompt the user again
    echo "Error: Coolify SSH key cannot be empty. Please try again."
  fi
done

########################################
# Time & updates
########################################

# Set timezone to Switzerland and enable NTP
timedatectl set-timezone "Europe/Zurich"
timedatectl set-ntp true

# Update the system
apt-get update
apt-get upgrade -y

########################################
# Users
########################################

# Create sudo user
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$ADMIN_USER"
  usermod -aG sudo "$ADMIN_USER"
fi

# Allow sudo user to run commands without password (REQUIRED for Coolify)
# We write to a separate file in sudoers.d for cleanliness
if id "$ADMIN_USER" >/dev/null 2>&1; then
  echo "$ADMIN_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$ADMIN_USER
  chmod 0440 /etc/sudoers.d/$ADMIN_USER
fi

# Set up SSH keys for admin user
if id "$ADMIN_USER" >/dev/null 2>&1; then
  ADMIN_HOME="/home/$ADMIN_USER"
  mkdir -p "$ADMIN_HOME/.ssh"
  echo "$COOLIFY_KEY" > "$ADMIN_HOME/.ssh/authorized_keys"
  chmod 700 "$ADMIN_HOME/.ssh"
  chmod 600 "$ADMIN_HOME/.ssh/authorized_keys"
  chown -R "$ADMIN_USER:$ADMIN_USER" "$ADMIN_HOME/.ssh"
fi

# ============================================================================
# SYSCTL Kernel Hardening
# ============================================================================

cat > /etc/sysctl.d/99-hardening.conf <<EOF
# Disable ICMP redirects (prevent MITM via routing table manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Don't send ICMP redirects (this server is not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1

# Disable source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log packets with impossible source addresses (spoofing detection)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcast pings (Smurf attack protection)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering (IP spoofing protection)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF

# Apply immediately
sysctl --system

########################################
# Secure SSH
########################################

SSHD_CONFIG="/etc/ssh/sshd_config"

# Change SSH port to 1022 (replace existing Port line)
if grep -qE '^[#[:space:]]*Port[[:space:]]+[0-9]+' "$SSHD_CONFIG"; then
  sed -i 's/^[#[:space:]]*Port[[:space:]]\+[0-9]\+/Port 1022/' "$SSHD_CONFIG"
else
  echo "Port 1022" >> "$SSHD_CONFIG"
fi

# Disable root login
if grep -qE '^[#[:space:]]*PermitRootLogin' "$SSHD_CONFIG"; then
  sed -i 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
else
  echo "PermitRootLogin no" >> "$SSHD_CONFIG"
fi

# Explicitly block password auth
if grep -qE '^[#[:space:]]*PasswordAuthentication' "$SSHD_CONFIG"; then
  sed -i 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
else
  echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
fi

# Explicitly enable public key authentication
if grep -qE '^[#[:space:]]*PubkeyAuthentication' "$SSHD_CONFIG"; then
  sed -i 's/^[#[:space:]]*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSHD_CONFIG"
else
  echo "PubkeyAuthentication yes" >> "$SSHD_CONFIG"
fi

# Forbid empty passwords
if grep -qE '^[#[:space:]]*PermitEmptyPasswords' "$SSHD_CONFIG"; then
  sed -i 's/^[#[:space:]]*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONFIG"
else
  echo "PermitEmptyPasswords no" >> "$SSHD_CONFIG"
fi

# Limit auth tries
if grep -qE '^[#[:space:]]*MaxAuthTries' "$SSHD_CONFIG"; then
  sed -i 's/^[#[:space:]]*MaxAuthTries.*/MaxAuthTries 3/' "$SSHD_CONFIG"
else
  echo "MaxAuthTries 3" >> "$SSHD_CONFIG"
fi

# Limit concurrent sessions
if grep -qE '^[#[:space:]]*MaxSessions' "$SSHD_CONFIG"; then
  sed -i 's/^[#[:space:]]*MaxSessions.*/MaxSessions 3/' "$SSHD_CONFIG"
else
  echo "MaxSessions 3" >> "$SSHD_CONFIG"
fi

# Shorten login grace time
if grep -qE '^[#[:space:]]*LoginGraceTime' "$SSHD_CONFIG"; then
  sed -i 's/^[#[:space:]]*LoginGraceTime.*/LoginGraceTime 15/' "$SSHD_CONFIG"
else
  echo "LoginGraceTime 15" >> "$SSHD_CONFIG"
fi

# Only allow the admin user and the current user to SSH
CURRENT_USER="$(whoami)"
ALLOWED_USERS="$ADMIN_USER"
if [ "$CURRENT_USER" != "$ADMIN_USER" ]; then
  ALLOWED_USERS="$ADMIN_USER $CURRENT_USER"
fi

if grep -qE '^[#[:space:]]*AllowUsers' "$SSHD_CONFIG"; then
  sed -i "s/^[#[:space:]]*AllowUsers.*/AllowUsers $ALLOWED_USERS/" "$SSHD_CONFIG"
else
  echo "AllowUsers $ALLOWED_USERS" >> "$SSHD_CONFIG"
fi

# Disable X11 forwarding
if grep -qE '^[#[:space:]]*X11Forwarding' "$SSHD_CONFIG"; then
  sed -i 's/^[#[:space:]]*X11Forwarding.*/X11Forwarding no/' "$SSHD_CONFIG"
else
  echo "X11Forwarding no" >> "$SSHD_CONFIG"
fi

# Disable TCP forwarding
if grep -qE '^[#[:space:]]*AllowTcpForwarding' "$SSHD_CONFIG"; then
  sed -i 's/^[#[:space:]]*AllowTcpForwarding.*/AllowTcpForwarding no/' "$SSHD_CONFIG"
else
  echo "AllowTcpForwarding no" >> "$SSHD_CONFIG"
fi

# Disable agent forwarding
if grep -qE '^[#[:space:]]*AllowAgentForwarding' "$SSHD_CONFIG"; then
  sed -i 's/^[#[:space:]]*AllowAgentForwarding.*/AllowAgentForwarding no/' "$SSHD_CONFIG"
else
  echo "AllowAgentForwarding no" >> "$SSHD_CONFIG"
fi

# Validate SSH config and restart SSH or error
if ! sshd -t; then
  echo "========================================" >&2
  echo "ERROR: sshd config is invalid!" >&2
  echo "SSH was NOT restarted." >&2
  echo "Please fix $SSHD_CONFIG manually." >&2
  echo "========================================" >&2
  read -p "Press Enter to exit..."
  exit 1
fi

systemctl restart ssh

########################################
# Firewall (UFW)
########################################

# Set explicit defaults
ufw default deny incoming
ufw default allow outgoing

# Allow web traffic (TCP)
ufw allow 80/tcp
ufw allow 443/tcp

# Allow SSH (port 1022/TCP)
ufw allow 1022/tcp

# Enable firewall (non-interactive)
yes | ufw enable

########################################
# Fail2ban
########################################

# Install fail2ban
apt-get install -y fail2ban

# Configure fail2ban
cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 48h
findtime = 10h
maxretry = 10

[sshd]
enabled  = true
port     = 1022
logpath  = /var/log/auth.log
backend  = systemd
maxretry = 10
findtime = 10h
bantime  = 48h
EOF

systemctl enable --now fail2ban

########################################
# Email & Notification Setup
########################################

# Install msmtp (sends mail) and bsd-mailx (provides the 'mail' command)
apt-get update
if ! apt-get install -y msmtp msmtp-mta bsd-mailx; then
  echo "ERROR: Failed to install msmtp packages." >&2
  read -p "Press Enter to exit..."
  exit 1
fi

# Determine TLS mode based on port
if [ "$SMTP_PORT" = "465" ]; then
  TLS_STARTTLS="off"
else
  TLS_STARTTLS="on"
fi

# Create msmtp config file with placeholders
cat > /etc/msmtprc <<'EOF'
defaults
auth           on
tls            on
tls_starttls   __TLS_STARTTLS__
tls_trust_file /etc/ssl/certs/ca-certificates.crt
tls_min_protocol tlsv1.2
logfile        /var/log/msmtp.log

account        default
host           __SMTP_HOST__
port           __SMTP_PORT__
from           __EMAIL_FROM__
user           __SMTP_USER__
password       __SMTP_PASS__
EOF

# Replace place holders with values
# Done separately to avoid issues with special caracters in the variables
sed -i "s|__TLS_STARTTLS__|${TLS_STARTTLS}|g" /etc/msmtprc
sed -i "s|__SMTP_HOST__|${SMTP_HOST}|g" /etc/msmtprc
sed -i "s|__SMTP_PORT__|${SMTP_PORT}|g" /etc/msmtprc
sed -i "s|__EMAIL_FROM__|${EMAIL_FROM}|g" /etc/msmtprc
sed -i "s|__SMTP_USER__|${SMTP_USER}|g" /etc/msmtprc
sed -i "s|__SMTP_PASS__|${SMTP_PASS}|g" /etc/msmtprc

# Secure the config file (contains password)
# Owned by root, readable by msmtp group so non-root users can send mail
chown root:msmtp /etc/msmtprc
chmod 640 /etc/msmtprc

unset SMTP_PASS

# Test email
echo "Test email from your VPS setup script." | mail -s "VPS Setup Test" "$EMAIL_DEST"

########################################
# Automated Updates (Split Schedule)
########################################

apt-get install -y unattended-upgrades

# This config is used by the Daily run for security updates.
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};

Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";

// EMAIL SETTINGS
Unattended-Upgrade::Mail "$EMAIL_DEST";
Unattended-Upgrade::MailReport "on-change";
EOF

# Disable default systemd timers (we want full control via Cron)
systemctl disable --now apt-daily.timer
systemctl disable --now apt-daily.service
systemctl disable --now apt-daily-upgrade.timer
systemctl disable --now apt-daily-upgrade.service

# Create the Cron Schedule
# We need to detect the distro codename (e.g., jammy, bookworm) to inject it into the cron command
# because cron doesn't understand the \${distro...} variables natively in the command line args.
CODENAME=$(lsb_release -sc)
DISTRO_ID=$(lsb_release -si)

cat > /etc/cron.d/automated_updates <<EOF
# DAILY (Every day at 03:00) - Security Only
0 3 * * * root /usr/bin/flock -w 300 /var/lock/apt-update.lock bash -c 'apt-get update && /usr/bin/unattended-upgrade -v'

# WEEKLY (Tuesday at 03:30) - Standard Updates + Base
30 3 * * 2 root /usr/bin/flock -w 300 /var/lock/apt-update.lock bash -c 'apt-get update && /usr/bin/unattended-upgrade -v -o "Unattended-Upgrade::Allowed-Origins::=${DISTRO_ID}:${CODENAME}-updates" -o "Unattended-Upgrade::Allowed-Origins::=${DISTRO_ID}:${CODENAME}"'
EOF

########################################
# Reboot notification email
########################################

(crontab -l 2>/dev/null; echo "@reboot echo 'The server $(hostname) has successfully rebooted and is back online.' | mail -s 'Server Rebooted' $EMAIL_DEST") | crontab -

########################################
# Limit docker log size
########################################

mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
  }
}
EOF

########################################
# Cleanup
########################################

# Attempt to clear the in-memory and on-disk history for this session
echo "--- Cleaning up ---"
history -c || true
history -w || true

# Overwrite root's bash history file (if it exists)
if [ -f /root/.bash_history ]; then
  : > /root/.bash_history
fi

clear
echo "###########################################################"
echo "Setup Complete!"
echo "1. Your SSH port is now 1022."
echo "2. Root login is DISABLED."
echo "3. You must login as: $ADMIN_USER"
echo "4. Connect this server to Coolify using port 1022 and user $ADMIN_USER"
echo "###########################################################"
