#!usr/bin/bash

#This script is used to harden the security of the system
################################################################################

#Disable automounting
apt purge autofs

#Ensure address space lyaout randomization(ASLR)
sysctl -w kernel.randomize_va_space=2

#Ensure prelink is not installed
prelink -ua #Running to restore binaries to normal
apt purge prelink #uninstalling prelink.

#Ensure Automatic Error Reporting is not enabled
apt purge apport

#Ensure AppArmor is installed
apt install apparmor

#Ensure all AppArmor Profiles are in enforce mode
aa-enforce /etc/apparmor.d/*

#Ensure ntp is enabled and running
systemctl unmask ntp.service #unmasking the ntp daemon

systemctl --now enable ntp.service #enabling and starting the ntp daemon

#Ensure iptables packages are installed
apt install iptables iptables-persistent

#Ensure ufw is uninstalled or disabled with iptables
apt purge ufw

#Configure IPv4 iptables
# Flush IPtables rules
iptables -F
# Ensure default deny firewall policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
# Ensure loopback traffic is configured
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
# Ensure outbound and established connections are configured
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
# Open inbound ssh(tcp port 22) connections
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

#Configure IPv6 iptables
# Flush ip6tables rules
ip6tables -F
# Ensure default deny firewall policy
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
# Ensure loopback traffic is configured
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -s ::1 -j DROP
# Ensure outbound and established connections are configured
ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
# Open inbound ssh(tcp port 22) connections
ip6tables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

#Ensure only authorized users own audit log files
find $(dirname $(awk -F"=" '/^\s*log_file\s*=\s*/ {print $2}'
/etc/audit/auditd.conf | xargs)) -type f ! -user root -exec chown root {} +

#Ensure audit configuration files are owned by root
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user
root -exec chown root {} +

#Ensure audit tools are owned by root
chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace
/sbin/auditd /sbin/augenrules

#set permissions and ownership on the SSH host public key files
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-
wx {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown
root:root {} \;

#Ensure inactive password lock is 30 days or less
useradd -D -f 30


#Ensure default group for the root account is GID 0
usermod -g 0 root

#Ensure permissions on /etc/passwd- are configured
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-

#Ensure permissions on /etc/group are configured
chown root:root /etc/group
chmod u-x,go-wx /etc/group

#Ensure permissions on /etc/shadow are configured
chown root:root /etc/shadow
chown root:shadow /etc/shadow
#to remove excess permissions form /etc/shadow:
chmod u-x,g-wx,o-rwx /etc/shadow

#Ensure permissions on /etc/gshadow are configured
chown root:root /etc/gshadow
chown root:shadow /etc/gshadow
chmod u-x,g-wx,o-rwx /etc/gshadow

#Ensure accounts in /etc/passwd use shadowed passwords
sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd

#Ensure shadow group is empty
sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' /etc/group

######################################################################################
#Ensure mounting of cramfs filesystems is disabled

{
    l_mname="cramfs" # set module name
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install
\/bin\/(true|false)'; then
        echo -e " - setting module: \"$l_mname\" to be not loadable"
        echo -e "install $l_mname /bin/false" >>
/etc/modprobe.d/"$l_mname".conf
    fi
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo -e " - unloading module \"$l_mname\""
        modprobe -r "$l_mname"
    fi
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo -e " - deny listing \"$l_mname\""
        echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi
}

##########################################################################################
#Ensure mounting of squashfs filesystems is disabled

{
    l_mname="squashfs" # set module name
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install
\/bin\/(true|false)'; then
        echo -e " - setting module: \"$l_mname\" to be not loadable"
        echo -e "install $l_mname /bin/false" >>
/etc/modprobe.d/"$l_mname".conf
    fi
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo -e " - unloading module \"$l_mname\""
        modprobe -r "$l_mname"
    fi
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo -e " - deny listing \"$l_mname\""
        echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi
}

######################################################################################
#Ensure mounting of udf filesystems is disabled

{
    l_mname="udf" # set module name
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install
\/bin\/(true|false)'; then
        echo -e " - setting module: \"$l_mname\" to be not loadable"
        echo -e "install $l_mname /bin/false" >>
/etc/modprobe.d/"$l_mname".conf
    fi
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo -e " - unloading module \"$l_mname\""
        modprobe -r "$l_mname"
    fi
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo -e " - deny listing \"$l_mname\""
        echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi
}

#######################################################################################
#Disable USB Storage

{
    l_mname="usb-storage" # set module name
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install
\/bin\/(true|false)'; then
        echo -e " - setting module: \"$l_mname\" to be not loadable"
        echo -e "install $l_mname /bin/false" >>
/etc/modprobe.d/"$l_mname".conf
    fi
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo -e " - unloading module \"$l_mname\""
        modprobe -r "$l_mname"
    fi
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo -e " - deny listing \"$l_mname\""
        echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi
}

##########################################################################################
#Ensure permissions on SSH private host key files are configured

{
    l_skgn="ssh_keys" # Group designated to own openSSH keys
    l_skgid="$(awk -F: '($1 == "'"$l_skgn"'"){print $3}' /etc/group)"
    awk '{print}' <<< "$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat -L -c "%n %#a %U %G %g" {} +)" | (while read -r l_file l_model_owner l_group l_gid; do
        [ -n "$l_skgid" ] && l_cga="$l_skgn" || l_cga="root"
        [ "$l_gid" = "$l_skgid" ] && l_pmask="0137" || l_pmask="0177"
        l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
        if [ $(( $l_mode & $l_pmask )) -gt 0 ]; then
            echo -e " - File: \"$l_file\" is mode \"$l_mode\" changing to mode: \"$l_maxperm\""
            if [ -n "$l_skgid" ]; then
                chmod u-x,g-wx,o-rwx "$l_file"
            else
                chmod u-x,go-rwx "$l_file"
            fi
        fi
        if [ "$l_owner" != "root" ]; then
            echo -e " - File: \"$l_file\" is owned by: \"$l_owner\" changing owner to \"root\""
            chown root "$l_file"
        fi
        if [ "$l_group" != "root" ] && [ "$l_gid" != "$l_skgid" ]; then
            echo -e " - File: \"$l_file\" is owned by group \"$l_group\" should belong to group \"$l_cga\""
            chgrp "$l_cga" "$l_file"
        fi
    done
    )
}

##########################################################################################
#Ensure permissions on SSH public host key files are configured

find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;

##########################################################################################
#Ensure local interactive user home directories exist

{
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }'
/etc/passwd | while read -r user home; do
        if [ ! -d "$home" ]; then
            echo -e "\n- User \"$user\" home directory \"$home\" doesn't exist\n- creating home directory \"$home\"\n"
            mkdir "$home"
            chmod g-w,o-wrx "$home"
            chown "$user" "$home"
        fi
    done
}

##########################################################################################
#Ensure local interactive users own their home directories

{
    output=""
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }'
/etc/passwd | while read -r user home; do
        owner="$(stat -L -c "%U" "$home")"
        if [ "$owner" != "$user" ]; then
            echo -e "\n- User \"$user\" home directory \"$home\" is owned by user \"$owner\"\n - changing ownership to \"$user\"\n"
            chown "$user" "$home"
        fi
    done
}

##########################################################################################
#Ensure local interactive user home directories are mode 750 or more restrictive

{
    perm_mask='0027'
    maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }'
/etc/passwd | (while read -r user home; do
        mode=$( stat -L -c '%#a' "$home" )
        if [ $(( $mode & $perm_mask )) -gt 0 ]; then
            echo -e "- modifying User $user home directory: \"$home\"\n-removing excessive permissions from current mode of \"$mode\""
            chmod g-w,o-rwx "$home"
        fi
    done
    )
}

##########################################################################################
#Ensure no local interactive user has .netrc files

{
    perm_mask='0177'
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }'
/etc/passwd | while read -r user home; do
        if [ -f "$home/.netrc" ]; then
            echo -e "\n- User \"$user\" file: \"$home/.netrc\" exists\n -removing file: \"$home/.netrc\"\n"
            rm -f "$home/.netrc"
        fi
    done
}

##########################################################################################
#Ensure no local interactive user has .forward files

{
    output=""
    fname=".forward"
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }'
/etc/passwd | (while read -r user home; do
        if [ -f "$home/$fname" ]; then
            echo -e "$output\n- User \"$user\" file: \"$home/$fname\" exists\n - removing file: \"$home/$fname\"\n"
            rm -r "$home/$fname"
        fi
    done
    )
}

##########################################################################################
#Ensure no local interactive user has .rhosts files

{
    perm_mask='0177'
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }'
/etc/passwd | while read -r user home; do
        if [ -f "$home/.rhosts" ]; then
            echo -e "\n- User \"$user\" file: \"$home/.rhosts\" exists\n -removing file: \"$home/.rhosts\"\n"
            rm -f "$home/.rhosts"
        fi
    done
}

##########################################################################################
#Ensure local interactive user dot files are not group or world writable

{
    perm_mask='0022'
    valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
    awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | while read -r user home; do
        find "$home" -type f -name '.*' | while read -r dfile; do
            mode=$( stat -L -c '%#a' "$dfile" )
            if [ $(( $mode & $perm_mask )) -gt 0 ]; then
                echo -e "\n- Modifying User \"$user\" file: \"$dfile\"\n-removing group and other write permissions"
                chmod go-w "$dfile"
            fi
        done
    done
}

