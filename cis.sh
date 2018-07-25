#!/bin/bash

[ $(id -u) != 0 ] && echo "You are not root. Please login as root or run with sudo." && exit 1

echo "Updating apt cache"

  apt-get update > /dev/null

echo "Processing: 1.1.16 Ensure noexec option set on /dev/shm partition"

 mount -o remount,noexec /dev/shm

echo "Processing: 1.3.1 Ensure AIDE is installed"

 apt-get install -y aide aide-common

echo "Processing: 1.3.2 Ensure filesystem integrity is regularly checked"

  if  crontab -u root -l | grep -q "aide.conf --check"
    then
        echo "Cronjob is already set!"
    else
         crontab -u root -l > mycron
        echo "0 5 * * * /usr/bin/aide --config /etc/aide/aide.conf --check" >> mycron
        crontab mycron
        rm mycron
  fi

#  echo "Processing: 1.6.1.4 Ensure no unconfined daemons exist"



#  echo "Processing: 1.6.1.2 Ensure the SELinux state is enforcing"


echo "Processing: 2.1.1 Ensure chargen services are not enabled"

  sed -i "/\b\( ^chargen\)\b/d" /etc/services

echo "Processing: 2.1.2 Ensure daytime services are not enabled"

  sed -i "/\b\( ^daytime\)\b/d" /etc/services

echo "Processing: 2.1.3 Ensure discard services are not enabled"

  sed -i "/\b\( ^discard\)\b/d" /etc/services

echo "Processing: 2.1.4 Ensure echo services are not enabled"

  sed -i "/\b\( ^echo\)\b/d" /etc/services

echo "Processing: 2.1.5 Ensure time services are not enabled"

  sed -i "/\b\( ^time\)\b/d" /etc/services

echo "Processing: 2.1.6 Ensure rsh server is not enabled"

  sed -i "/\b\( ^exec\)\b/d" /etc/services
  sed -i "/\b\( ^login\)\b/d" /etc/services
  sed -i "/\b\( ^shell\)\b/d" /etc/services

echo "Processing: 2.1.7 Ensure talk server is not enabled"

  sed -i "/\b\( talk\)\b/d" /etc/services

echo "Processing: 2.1.8 Ensure telnet server is not enabled"

  sed -i "/\b\( ^telnet\)\b/d" /etc/services

echo "Processing: 2.1.9 Ensure tftp server is not enabled"

  sed -i "/\b\( ^tftp\)\b/d" /etc/services

echo "Processing: 2.2.1.1 Ensure time synchronization is in use"

  apt-get install -y chrony

# echo "Processing: 2.2.2 Ensure X Window System is not installed"
# Server only!!!

#  apt-get remove -y xserver-xorg*

echo "Processing: 2.2.3 Ensure Avahi Server is not enabled"

  systemctl disable avahi-daemon

echo "Processing: 2.2.16 Ensure rsync service is not enabled"

  systemctl disable rsync

echo "Processing: 3.1.2 Ensure packet redirect sending is disabled"

  sysctl -w net.ipv4.conf.all.send_redirects=0
  sysctl -w net.ipv4.conf.default.send_redirects=0
  sysctl -w net.ipv4.route.flush=1

echo "Processing: 3.6.2-3.6.4 applying firewall policy"

  iptables -P INPUT DROP
  iptables -P OUTPUT DROP
  iptables -P FORWARD DROP

  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A INPUT -s 127.0.0.0/8 -j DROP

  iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
  #if You want to open input access just add string under example below 
  #iptables -A INPUT -p tcp -s <network/mask> --dport <app_port> -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
  iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
  iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

  iptables-save > /etc/network/iptables.rules

  echo -e '#!/bin/bash \niptables-restore < /etc/network/iptables.rules' > /etc/network/if-pre-up.d/iptables
  chmod +x /etc/network/if-pre-up.d/iptables

echo "Processing: 5.1.2 Ensure permissions on /etc/crontab are configured"

  chmod og-rwx /etc/crontab

echo "Processing: 5.1.3 Ensure permissions on /etc/cron.hourly are configured"

  chmod og-rwx /etc/cron.hourly

echo "Processing: 5.1.4 Ensure permissions on /etc/cron.daily are configured"

  chmod og-rwx /etc/cron.daily

echo "Processing: 5.1.5 Ensure permissions on /etc/cron.weekly are configured"

  chmod og-rwx /etc/cron.weekly

echo "Processing: 5.1.6 Ensure permissions on /etc/cron.monthly are configured"

  chmod og-rwx /etc/cron.monthly

echo "Processing: 5.1.7 Ensure permissions on /etc/cron.d are configured"

  chmod og-rwx /etc/cron.d

echo "Processing: 5.1.8 Ensure at/cron is restricted to authorized users"

  if [[ -f /etc/cron.allow && -f /etc/at.allow ]]
    then
        echo "Files exist!"
    else
         touch /etc/cron.allow /etc/at.allow
  fi

  chmod og-rwx /etc/cron.allow /etc/at.allow
  chown root:root /etc/cron.allow /etc/at.allow

echo "Processing: 5.2.1 Ensure permissions on /etc/ssh/sshd_config is configured"

  chmod og-rwx /etc/ssh/sshd_config

echo "Processing: 5.2.3 Ensure SSH LogLevel is set to INFO"

  if grep -q "LogLevel INFO" /etc/ssh/sshd_config
    then
        echo "Value is set!"
    else
        echo LogLevel INFO >> /etc/ssh/sshd_config
  fi

echo "Processing: 5.2.4 Ensure SSH X11 forwarding is disabled"

  sed -i "/\b\(X11Forwarding\)\b/d" /etc/ssh/sshd_config
  echo X11Forwarding no >> /etc/ssh/sshd_config

echo "Processing: 5.2.5 Ensure SSH MaxAuthTries is set to 4 or less"

  if grep -q "MaxAuthTries 4" /etc/ssh/sshd_config
    then
        echo "Value is set!"
    else
        echo MaxAuthTries 4 >> /etc/ssh/sshd_config
  fi

echo "Processing: 5.2.8 Ensure SSH root login is disabled"

  if grep -q "PermitRootLogin no" /etc/ssh/sshd_config
    then
        echo "Value is set!"
    else
        echo PermitRootLogin no >> /etc/ssh/sshd_config
  fi


echo "Processing: 5.2.11 Ensure only approved MAC algorithms are used"

  if grep -q 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' /etc/ssh/sshd_config
    then
        echo "Value is set!"
    else
        echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config
  fi


echo "Processing: 5.2.12 Ensure SSH Idle Timeout Interval is configured"

  if grep -q “ClientAliveInterval 300” /etc/ssh/sshd_config && grep -q “ClientAliveCountMax 0” /etc/ssh/sshd_config
    then
        echo "Values are set!"
    else
        echo 'ClientAliveInterval 300\nClientAliveCountMax 0' >> /etc/ssh/sshd_config
  fi

echo "Processing: 5.2.13 Ensure SSH LoginGraceTime is set to one minute or less"

  if grep -q “LoginGraceTime 60” /etc/ssh/sshd_config
    then
        echo "Value is set!"
    else
        echo LoginGraceTime 60 >> /etc/ssh/sshd_config
  fi

echo "Processing: 5.2.15 Ensure SSH warning banner is configured"

  if grep -q “Banner /etc/issue.net” /etc/ssh/sshd_config
    then
        echo "Value is set!"
    else
        echo Banner /etc/issue.net >> /etc/ssh/sshd_config
  fi

echo "Processing: 5.3.1 Ensure password creation requirements are configured"

  apt-get install -y libpam-pwquality

  if grep -q “minlen = 8” /etc/security/pwquality.conf && grep -q “dcredit = -1” /etc/security/pwquality.conf && grep -q “ucredit = -1” /etc/security/pwquality.conf && grep -q “ocredit = -1” /etc/security/pwquality.conf && grep -q “lcredit = -1” /etc/security/pwquality.conf
    then
        echo "Values are set!"
    else
        echo -e 'minlen = 8\ndcredit = -1\nucredit = -1\nocredit = -1\nlcredit = -1' >> /etc/security/pwquality.conf
  fi


echo "Processing: 5.3.2 Ensure lockout for failed password attempts is configured"

  sed -i "/\b\(required\)\b/d" /etc/pam.d/common-auth
  echo auth required pam_tally2.so onerr=fail audit silent deny=10 unlock_time=90 >> /etc/pam.d/common-auth

echo "Processing: 5.3.3 Ensure password reuse is limited"

  sed -i "/\b\(required\)\b/d" /etc/pam.d/common-password
  echo password required pam_pwhistory.so remember=5 >> /etc/pam.d/common-password

echo "Processing: 5.3.4 Ensure password hashing algorithm is SHA-512"

  sed -i "/\b\(success=\)\b/d" /etc/pam.d/common-password
  echo password [success=1 default=ignore] pam_unix.so sha512 >> /etc/pam.d/common-password

echo "Processing: 5.4.1.1 Ensure password expiration is 365 days or less"
echo "Processing: 5.4.1.2 Ensure minimum days between password changes is 7 or more"
echo "Processing: 5.4.1.3 Ensure password expiration warning days is 7 or more"

for i in $(awk -F':' '/\/home.*sh/ { print $1 }' /etc/passwd); do chage -m 7 -M 90 -W 7 $i; done
  
 

echo "Processing: 5.4.1.4 Ensure inactive password lock is 30 days or less"

  useradd -D -f 30

echo "Processing: 5.4.4 Ensure default user umask is 027 or more restrictive"

  if grep -Rq "umask" /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh
    then
        echo "Value is set!"
    else
        echo "umask 027" | tee -a /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh
  fi

echo "Processing: 5.4.5 Ensure default user shell timeout is 900 seconds or less"

  if grep -Rq "TMOUT" /etc/bash.bashrc /etc/profile
    then
        echo "Value is set!"
    else
        echo "TMOUT = 600" | tee -a /etc/bash.bashrc /etc/profile
  fi



echo "Success! Please reboot the machine for all changes to apply"
