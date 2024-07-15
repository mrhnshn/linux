#!/bin/bash
###requirements###
sudo apt install --no-install-recommends lvm2 systemd-timesyncd ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-compose-plugin


###cephadm installation###
wget -O /tmp/cephadm https://github.com/ceph/ceph/raw/pacific/src/cephadm/cephadm
chmod +x /tmp/cephadm
sudo /tmp/cephadm add-repo --release pacific
sudo /tmp/cephadm install

#deploy cluster
echo "cephadm ALL = (root) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/cephadm
chmod 440 /etc/sudoers.d/cephadm
chown root: /etc/sudoers.d/cephadm
sudo cephadm bootstrap --mon-ip <ceph-public-network> --cluster-network <ceph-private-network> --ssh-user cephadm --dashboard-crt <cert.pem> --dashboard-key <privkey.pem>

#add host
ssh-copy-id -f -i /etc/ceph/ceph.pub cephadm@<host-ip>
sudo cephadm shell
ceph orch host add <host-name> <host-ip> --labels _admin

#osd initial setup
sudo cephadm shell
ceph orch apply osd --all-available-devices --unmanaged=true

#sysctl configuration
echo "
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 16384 16777216
net.core.rmem_max=16777216
net.core.wmem_max=16777216
vm.swappiness=0
"| sudo tee /etc/sysctl.d/ceph.conf


#-----#
###deploy cephfs service###
sudo cephadm shell
ceph fs volume create <filesystem-name>

#mount cephfs
sudo cephadm shell
[2]ceph config generate-minimal-conf
[3]ceph fs authorize <filesystem-name> client.<client-hostname> / rw

#on client
sudo mkdir -p -m 755 /etc/ceph
echo [2] | sudo tee /etc/ceph/ceph.conf
sudo chmod 644 /etc/ceph/ceph.conf
echo [3] | sudo tee /etc/ceph/ceph.client.`echo $HOSTNAME`.keyring
sudo chmod 600 /etc/ceph/ceph.client.`echo $HOSTNAME`.keyring

sudo apt install ceph-common
sudo mkdir /mnt/cephfs
sudo mount -t ceph <ceph-node-ip>,<ceph-node-ip>:/ /mnt/cephfs/ -o name=`echo $HOSTNAME`,secret=$(grep key /etc/ceph/ceph.client.`echo $HOSTNAME`.keyring| cut -d' ' -f4)


#-----#
###deploy ceph block device###
sudo cephadm shell

#create a new pool named `rbd` on ceph dashboard
rbd pool init rbd

#mount block device
sudo cephadm shell
[2] ceph auth get-or-create client.rbd-user mon 'profile rbd' osd 'profile rbd pool=rbd' mgr 'profile rbd pool=rbd'

#on client
sudo mkdir -p -m 755 /etc/ceph
echo [2] | sudo tee /etc/ceph/ceph.client.rbd-user.keyring
sudo chmod 644 /etc/ceph/ceph.client.rbd-user.keyring

#map rbd image
sudo rbd map <image-name> --keyring /etc/ceph/ceph.client.rbd-user.keyring --name client.rbd-user /dev/rbd0

#unmap rbd image
sudo rbd unmap /dev/rbd/rbd/<image-name>


#-----#
###ceph object storage###
#create a new rgw service on ceph dashboard
sudo cephadm shell
ceph dashboard set-rgw-credentials
ceph dashboard set-rgw-api-ssl-verify False

#mount object storage
#create a new object gateway user on ceph dashboard, get access and secret keys.

#on client
sudo apt install awscli
mkdir ~/.aws
echo "
[profile ceph]
output = json
"| tee ~/.aws/config

echo "
[ceph]
aws_access_key_id = <access-key>
aws_secret_access_key = <secret-key>
"| tee ~/.aws/credentials

#create a new bucket
aws --profile=ceph --endpoint=https://<ceph-node-ip>:8000 s3 mb s3://<bucket-name>

#list directory
aws --profile=ceph --endpoint=https://<ceph-node-ip>:8000 s3 ls

#upload a file
aws --profile=ceph --endpoint=https://<ceph-node-ip>:8000 s3 cp <file-to-upload> s3://<bucket-name>
