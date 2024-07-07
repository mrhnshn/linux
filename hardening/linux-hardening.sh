#!/bin/bash
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
#sed -i 's/^UMASK.*/UMASK 077/g' /etc/login.defs
sed -i 's/.*SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 99999/g' /etc/login.defs
sed -i 's/.*SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS 99999/g' /etc/login.defs

#sed -i "s/auth \+sufficient pam_rootok.so/auth required pam_wheel.so use_uid group=<user>/g" /etc/pam.d/su

echo '* hard core 0' > /etc/security/limits.conf
echo 'APT::Sandbox::Seccomp "true";' > /etc/apt/apt.conf.d/40sandbox
grep -qx 'Compress=yes' /etc/systemd/journald.conf || echo 'Compress=yes' >> /etc/systemd/journald.conf

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
