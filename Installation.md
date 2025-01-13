# Jetson Orin NX

## Fix wifi  
```
sudo apt update && sudo apt upgrade
sudo apt install iwlwifi-modules
```

## Exfat
```
sudo add-apt-repository universe
sudo apt update
sudo apt install exfatprogs
# sudo apt install exfat-fuse
```

## Install tools  
Basic tools  
```
sudo apt install nano
# Chromium (UI)
# Code (terminal)
```
jtop  
```
sudo apt install python3-pip
sudo pip3 install -U jetson-stats
jtop
```

## Remote, login
- auto login (user)
- power settings: don't switch off screen
- delete keyring password (app)
- enable remote desktop sharing, vnc (-> use password!)
- install xrdp (optional)
```
sudo apt install xrdp
```

## SSH
```
sudo apt-get update && sudo apt-get install openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh
```
- put public key(s) to folder `~/.ssh/authorized_keys` for remote connections  
- generate key in `~/.ssh` using `ssh-keygen` or put existing private/pub key pair to connect to visualstudio.com or other sites
- secure copied keys, e.g.: `chmod 600 /home/jetson/.ssh/id_rsa`

## Swapfile
https://www.jetson-ai-lab.com/tips_ram-optimization.html  
https://github.com/dusty-nv/jetson-containers/blob/master/docs/setup.md
```
sudo systemctl disable nvzramconfig
sudo fallocate -l 16G /mnt/16GB.swap
sudo chmod 600 /mnt/16GB.swap
sudo mkswap /mnt/16GB.swap
sudo swapon /mnt/16GB.swap
echo '/mnt/16GB.swap none swap sw 0 0' | sudo tee -a /etc/fstab
```

## Create nova_ssd for Docker and ROS
```
sudo mkdir -p /mnt/nova_ssd
sudo mount /dev/nvme0n1 /mnt/nova_ssd
sudo chown ${USER}:${USER} /mnt/nova_ssd
```

## Docker
Docker user, group and groups permissions
```
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
docker run hello-world
# 'reboot' if necessary
```

Move Docker to nova_ssd:
```
sudo systemctl stop docker
sudo du -csh /var/lib/docker/ && \
    sudo mkdir /mnt/nova_ssd/docker && \
    sudo rsync -axPS /var/lib/docker/ /mnt/nova_ssd/docker/ && \
    sudo du -csh  /mnt/nova_ssd/docker/
```

Edit daemon.json set set default runtime and location
```
sudo nano /etc/docker/daemon.json
```
```json
{
    "runtimes": {
        "nvidia": {
            "path": "nvidia-container-runtime",
            "runtimeArgs": []
        }
    },
    "default-runtime": "nvidia",
    "data-root": "/mnt/nova_ssd/docker"
}
```

Remove old Docker folder, restart service and check logs
```
sudo mv /var/lib/docker /var/lib/docker.old
sudo systemctl daemon-reload && \
    sudo systemctl restart docker && \
    sudo journalctl -u docker
```
