#!/bin/bash
clear
###variables###
DISTRO_ID=$(grep -w '^ID' /etc/os-release | cut -d'=' -f2)
DISTRO_VER=$(grep -w '^VERSION_CODENAME' /etc/os-release | cut -d'=' -f2)
PASSWORD="aoxungaikeeyeenuC1oomoo7quohw7oo"
SERVER_NAME="fenrir"
TIMEZONE="Europe/Istanbul"
USER="borcott"


###functions###
function exit_script() {
  echo "| INFO  | Script Finished - $(date +'%F %T')"
  exit 1
}

echo "| INFO  | Script Started - $(date +'%F %T')"
echo -e "| INFO  | This script is prepared for Debian 12 (bookworm) & Ubuntu 22.04 (jammy) & Ubuntu 24.04 (noble) releases.\n"


###check requirements###
#check effective user id
if [[ $EUID -eq 0 ]]
then
  echo "| OK    | Check Effective User ID"
else
  echo "| ERROR | Check Effective User ID"
  echo "|       | This script must be run as root."
  exit_script
fi

#check internet connection
if [[ -x $(command -v ping) ]]
then
  if ping -c1 -4 -q google.com &>/dev/null
  then
    echo "| OK    | Check Internet Connection"
  else
    echo "| ERROR | Check Internet Connection"
    echo "|       | Internet connection is not available."
    exit_script
  fi
else
  echo "| WARN  | Check Internet Connection"
  echo "|       | 'ping' command is missing or not configured/installed properly."
fi

#check distro version
if [[ $DISTRO_VER == "noble" || $DISTRO_VER == "jammy" || $DISTRO_VER == "bookworm" ]]
then
  echo "| OK    | Check Distro Version"
else
  echo "| ERROR | Check Distro Version"
  echo "|       | The script has been halted due to a version mismatch."
  exit_script
fi


###configurations###
#user creation
if [[ "$USER" ]] && [[ "$PASSWORD" ]]
then
  if [[ -z $(cut -d':' -f1 /etc/passwd | grep $USER) ]]
  then
    groupadd -g 2000 $USER
    useradd -m -s /bin/bash -g 2000 -u 2000 $USER
    usermod -aG sudo $USER
    echo "$USER:$PASSWORD" | chpasswd
    echo "| OK    | User Creation"
    echo "|       | The user '$USER' has been successfully created."
  else
    echo "| WARN  | User Creation"
    echo "|       | The user '$USER' already exists. No changes were made."
  fi
else
  echo "| ERROR | User Creation"
  echo "|       | The required variables for the user creation are missing."
fi

#set up root password
if [[ "$PASSWORD" ]]
then
  echo "root:$PASSWORD" | chpasswd
  echo "| OK    | Set Up Root Password"
  echo "|       | Root password has been successfully set."
else
  echo "| ERROR | Set Up Root Password"
  echo "|       | The required variable for setting up the root password is missing."
fi

#configure hostname
hostnamectl set-hostname $SERVER_NAME
if [[ $(cat /etc/hostname) == $SERVER_NAME ]]
then
  echo "| OK    | Configure Hostname"
else
  echo "| ERROR | Configure Hostname"
fi

#configure timezone
timedatectl set-timezone $TIMEZONE
dpkg-reconfigure -f noninteractive tzdata &>/dev/null
if [[ $(timedatectl show | grep "^Timezone" | cut -d'=' -f2) == $TIMEZONE ]]
then
  echo "| OK    | Configure Timezone"
else
  echo "| ERROR | Configure Timezone"
fi

#configure '/etc/hosts'
echo -e "127.0.0.1 localhost\n127.0.1.1 $SERVER_NAME" > /etc/hosts
echo "| OK    | Configure '/etc/hosts'"

#configure dns
chattr -i /etc/resolv.conf &>/dev/null
rm -rf /etc/resolv.*
echo -e 'nameserver 1.1.1.1\nnameserver 1.0.0.1' > /etc/resolv.conf
chmod --quiet 644 /etc/resolv.conf
chattr +i /etc/resolv.conf
echo "| OK    | Configure DNS"

#configure apt repository
if [[ "$DISTRO_ID" == "debian" ]]
then
  echo "
deb http://deb.debian.org/debian $DISTRO_VER main contrib non-free-firmware
deb http://security.debian.org/debian-security $DISTRO_VER-security main contrib non-free-firmware
  " > /etc/apt/sources.list
elif [[ "$DISTRO_ID" == "ubuntu" ]]
then
  echo "
deb http://archive.ubuntu.com/ubuntu/ $DISTRO_VER main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $DISTRO_VER-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $DISTRO_VER-security main restricted universe multiverse
  " > /etc/apt/sources.list
fi
rm -rf /etc/apt/sources.list.d
apt update &>/dev/null
echo "| OK    | Configure APT Repository"

#Remove unnecessary packages
export DEBIAN_FRONTEND=noninteractive
apt purge -y --auto-remove alsa-topology-conf alsa-ucm-conf amazon-ec2-utils amd64-microcode apparmor apt-listchanges apt-utils avahi-autoipd awscli bind9-host bluetooth bluez busybox cloud-guest-utils cloud-utils debconf-i18n dictionaries-common discover discover-data dmidecode eject emacsen-common ethtool iamerican ibritish ienglish-common isc-dhcp-common ispell laptop-detect logrotate lsb-release manpages nano netbase netplan.io nftables os-prober pci.ids pciutils powertop psmisc reportbug shared-mime-info socat task-english task-laptop tasksel tasksel-data unattended-upgrades usbutils util-linux-locales vim-tiny wamerican whiptail wireless-regdb xdg-user-dirs &>/dev/null
apt autopurge -y &>/dev/null
echo "| OK    | Remove Unnecessary Packages"

#install required packages
apt install --no-install-recommends -y arp-scan bash-completion ca-certificates cron curl dbus dialog fdisk file htop ifupdown iproute2 iputils-ping isc-dhcp-client less man-db mtr-tiny netcat-openbsd nmap openssh-client openssh-server openssl procps pwgen screen systemd-timesyncd tcpdump traceroute tzdata unzip vim wget &>/dev/null
echo "| OK    | Install Required Packages"

#disable unnecessary services
systemctl disable apt-daily.timer apt-daily-upgrade.timer NetworkManager-dispatcher.service NetworkManager-wait-online.service systemd-network-generator.service systemd-networkd.service systemd-pstore.service systemd-resolved.service dpkg-db-backup.timer &>/dev/null
echo "| OK    | Disable Unnecessary Services"

#configure '/etc/bash.bashrc'
grep -q 'HISTTIMEFORMAT=' /etc/bash.bashrc || echo "
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
umask 0077
HISTTIMEFORMAT='%d/%m/%y %T '
alias ls='ls --color=auto'
alias ll='ls -alhF'
alias grep='grep --color=auto'
alias update='apt update && apt dist-upgrade --no-install-recommends && apt autopurge && apt clean && apt autoclean'
alias purge='rm -rvf /root/.wget-hsts /root/.lesshst /home/*/.lesshst /home/*/.wget-hsts /root/.viminfo /root/.cache /root/.gnupg /root/.vim /root/.config /root/.dbus /root/.local /root/.bash_history /initrd.img.old /vmlinuz.old /home/*/.cache /home/*/.bash_history /home/*/.viminfo /home/*/.pulse-cookie /home/*/.pki /home/*/.dbus /home/*/.xsession-errors /var/cache /var/log /tmp /var/tmp /var/lib/apt/*'
" >> /etc/bash.bashrc ; echo "| OK    | Configure '/etc/bash.bashrc'"

#configure '/etc/systemd/system.conf'
sed -i "s/#DefaultTimeoutStartSec=90s/DefaultTimeoutStartSec=40s/g" /etc/systemd/system.conf
sed -i "s/#DefaultTimeoutStopSec=90s/DefaultTimeoutStopSec=20s/g" /etc/systemd/system.conf
echo "| OK    | Configure '/etc/systemd/system.conf'"

#configure 'ifupdown'
if [[ $(dpkg --get-selections | grep -o ifupdown) ]]
then
  echo "
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
  " > /etc/network/interfaces
  rm -rf /etc/network/interfaces.d
  systemctl enable networking &>/dev/null
  echo "| OK    | Configure 'ifupdown'"
fi


###security hardening###
#sudo-hardening.sh
if [[ $(dpkg --get-selections | grep -o sudo) ]]
then
  mkdir /etc/sudoers.d &>/dev/null
  chmod --quiet 700 /etc/sudoers.d
  chown --quiet root: /etc/sudoers.d
  echo "Defaults use_pty" > /etc/sudoers.d/configuration
  chmod --quiet 440 /etc/sudoers.d/configuration
  chown --quiet root: /etc/sudoers.d/configuration
fi

#sshd-hardening.sh
if [[ $(dpkg --get-selections | grep -o openssh-server) ]]
then
  rm -rf /etc/ssh/sshd_config.d
  echo "
AcceptEnv LANG LC_*
AllowAgentForwarding no
AllowTcpForwarding no
AllowUsers $USER@*
ChallengeResponseAuthentication no
Ciphers aes128-ctr,aes128-gcm@openssh.com,aes192-ctr,aes256-ctr,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
ClientAliveCountMax 2
ClientAliveInterval 120
Compression no
GSSAPIAuthentication no
HostKey /etc/ssh/ssh_host_ed25519_key
KerberosAuthentication no
LoginGraceTime 20
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,sntrup761x25519-sha512@openssh.com
LogLevel VERBOSE
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
MaxAuthTries 2
MaxSessions 1
PasswordAuthentication yes
PermitEmptyPasswords no
PermitRootLogin no
PermitTunnel no
PermitUserEnvironment no
Port 34788
PrintMotd no
Protocol 2
TCPKeepAlive no
UseDNS no
UsePAM yes
X11Forwarding no
  " > /etc/ssh/sshd_config
  rm -f /etc/ssh/ssh_host_*
  dpkg-reconfigure -f noninteractive openssh-server &>/dev/null
fi

#linux-hardening.sh
touch /etc/cron.allow
touch /etc/at.allow
chown --quiet root:root /etc/group-
chmod --quiet u-x,go-rwx /etc/group-
chown --quiet root:root /etc/passwd-
chmod --quiet u-x,go-rwx /etc/passwd-
chown --quiet root:root /etc/crontab
chmod --quiet go-rwx /etc/crontab
chown --quiet root:root /etc/cron.hourly
chmod --quiet go-rwx /etc/cron.hourly
chown --quiet root:root /etc/cron.daily
chmod --quiet go-rwx /etc/cron.daily
chown --quiet root:root /etc/cron.weekly
chmod --quiet go-rwx /etc/cron.weekly
chown --quiet root:root /etc/cron.monthly
chmod --quiet go-rwx /etc/cron.monthly
chown --quiet -R root:root /etc/cron.d
chmod --quiet -R go-rwx /etc/cron.d
chown --quiet root:root /etc/cron.allow
chmod --quiet og-rwx /etc/cron.allow
chown --quiet root:root /etc/at.allow
chmod --quiet og-rwx /etc/at.allow
chown --quiet root:root /boot/grub/grub.cfg
chmod --quiet og-rwx /boot/grub/grub.cfg
chmod --quiet 700 /boot /usr/src /lib/modules /usr/lib/modules
chmod --quiet 600 /etc/ssh/sshd_config
rm -f /etc/motd
rm -f /etc/issue
rm -f /etc/issue.net
rm -f /etc/cron.deny
rm -f /etc/at.deny

for i in `grep '1[0-9][0-9][0-9]' /etc/passwd | cut -d':' -f1`; do gpasswd -d $i adm &>/dev/null; done
for i in `grep '1[0-9][0-9][0-9]' /etc/passwd | cut -d':' -f1`; do chmod --quiet 700 /home/$i; done
sed -i 's/^UMASK.*/UMASK 077/g' /etc/login.defs
sed -i 's/.*SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 99999/g' /etc/login.defs
sed -i 's/.*SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS 99999/g' /etc/login.defs

sed -i "s/auth \+sufficient pam_rootok.so/auth required pam_wheel.so use_uid group=$USER/g" /etc/pam.d/su

echo '* hard core 0' > /etc/security/limits.conf
echo 'APT::Sandbox::Seccomp "true";' > /etc/apt/apt.conf.d/40sandbox
grep -qx 'Compress=yes' /etc/systemd/journald.conf || echo 'Compress=yes' >> /etc/systemd/journald.conf

sed -i 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=2/g' /etc/default/grub
sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet ipv6.disable=1 net.ifnames=0 debugfs=off mce=0 randomize_kstack_offset=on vsyscall=none loglevel=0 amd_iommu=on intel_iommu=on efi=disable_early_pci_dma page_alloc.shuffle=1 init_on_alloc=1 init_on_free=1"/g' /etc/default/grub
update-initramfs -u &>/dev/null
update-grub &>/dev/null

#blacklist unnecessary kernel modules
echo "
blacklist af_802154
blacklist appletalk
blacklist atm
blacklist ax25
blacklist bluetooth
blacklist btbcm
blacklist btintel
blacklist btmtk
blacklist btrtl
blacklist btusb
blacklist can
blacklist cifs
blacklist cramfs
blacklist dccp
blacklist decnet
blacklist econet
blacklist firewire-core
blacklist freevxfs
blacklist gfs2
blacklist hfs
blacklist hfsplus
blacklist ipx
blacklist jffs2
blacklist ksmbd
blacklist kvm
blacklist kvm-amd
blacklist kvm-intel
blacklist n-hdlc
blacklist netrom
blacklist nfs
blacklist nfsv3
blacklist nfsv4
blacklist p8022
blacklist p8023
blacklist pcspkr
blacklist psnap
blacklist rds
blacklist rose
blacklist sctp
blacklist squashfs
blacklist thunderbolt
blacklist tipc
blacklist typec
blacklist typec_ucsi
blacklist ucsi_acpi
blacklist udf
blacklist uvcvideo
blacklist vivid
blacklist x25
" > /etc/modprobe.d/blacklist.conf

#configure sysctl parameters
rm -rf /etc/sysctl.*
echo "
dev.tty.ldisc_autoload=0
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_regular=2
fs.protected_symlinks=1
fs.suid_dumpable=0
kernel.core_pattern=|/bin/false
kernel.core_uses_pid=1
kernel.dmesg_restrict=1
kernel.kexec_load_disabled=1
kernel.kptr_restrict=2
kernel.nmi_watchdog=0
kernel.perf_event_paranoid=3
kernel.printk=3 3 3 3
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope=2
net.core.bpf_jit_harden=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.log_martians=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.ip_forward=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_sack=0
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_timestamps=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.all.use_tempaddr=2
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.default.use_tempaddr=2
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
vm.swappiness=0
vm.unprivileged_userfaultfd=0
" > /etc/sysctl.conf
mkdir /etc/sysctl.d &>/dev/null
ln -sf /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf
echo "| OK    | Security Hardening"
exit_script

