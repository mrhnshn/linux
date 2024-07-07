#!/bin/bash
if [[ $(dpkg --get-selections | grep -o openssh-server) ]]
then
  rm -rf /etc/ssh/sshd_config.d
  echo "
AcceptEnv LANG LC_*
AllowAgentForwarding no
AllowTcpForwarding no
#AllowUsers <user>@*
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
