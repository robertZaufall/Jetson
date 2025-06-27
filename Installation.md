# Jetson Orin NX

## Upgrade  
[Upgrade to 6.2.1](https://forums.developer.nvidia.com/t/jetpack-6-2-1-jetson-linux-36-4-4-is-now-live/337333/2)  


## JetPack 6.2 with SuperMode

[NVIDIA JetPack 6.2 Brings Super Mode to NVIDIA Jetson Orin Nano and Jetson Orin NX Modules](https://developer.nvidia.com/blog/nvidia-jetpack-6-2-brings-super-mode-to-nvidia-jetson-orin-nano-and-jetson-orin-nx-modules)  
[JetPack 6.2 Brings Super Mode to NVIDIA Jetson Orin Nano and Jetson Orin NX Modules](https://forums.developer.nvidia.com/t/jetpack-6-2-brings-super-mode-to-nvidia-jetson-orin-nano-and-jetson-orin-nx-modules/320343)  

Use new flash configuration `jetson-orin-nano-devkit-super.conf`.  
From the host:  
```
export JETPACK=$HOME/nvidia/nvidia_sdk/JetPack_6.2_Linux_.../Linux_for_Tegra

cd $JETPACK
sudo ./apply_binaries.sh
sudo ./tools/l4t_flash_prerequisites.sh

cd $JETPACK/tools
 sudo ./l4t_create_default_user.sh -u <user_name> -p <password>

sudo ./tools/kernel_flash/l4t_initrd_flash.sh --external-device nvme0n1p1 \
  -c tools/kernel_flash/flash_l4t_t234_nvme.xml -p "-c bootloader/generic/cfg/flash_t234_qspi.xml" \
  --showlogs --network usb0 jetson-orin-nano-devkit-super internal
```
On the Jetson:  
```
sudo apt update && sudo apt upgrade
sudo apt-get install nvidia-jetpack
```
https://docs.nvidia.com/jetson/archives/jetpack-archived/jetpack-62/install-setup/index.html#upgrade-jetpack  

[Exploring NVIDIA Jetson Orin Nano Super Mode performance using Generative AI](https://developer.ridgerun.com/wiki/index.php/Exploring_NVIDIA_Jetson_Orin_Nano_Super_Mode_performance_using_Generative_AI#Jetson_Orin_Nano_Super_mode_enabling_and_Generative_AI_running_instructions)  
http://www.yahboom.net/study/Jetson-Orin-NX

## Fix wifi  
```
sudo apt update && sudo apt upgrade
sudo apt install iwlwifi-modules
```

## Install tools  

See also https://github.com/jetsonhacks/jetson-orin-setup

Basic tools  
```
sudo apt install nano btop curl chromium-browser git-lfs -y
# usage: git lfs install
```
jtop  
```
sudo apt install python3-pip -y
sudo pip3 install -U jetson-stats
sudo systemctl restart jtop.service
jtop
```

## Remote, login
- auto login (user)
- delete keyring password (app)
- enable remote desktop sharing, vnc (-> use password!)
- power settings: don't switch off screen

## SSH
- put public key(s) to folder `~/.ssh/authorized_keys` for remote connections  
- generate key in `~/.ssh` using `ssh-keygen` or put existing private/pub key pair to connect to visualstudio.com or other sites
- secure copied keys, e.g.: `chmod 600 /home/jetson/.ssh/id_rsa`
- VSCode: if key exists `ssh-keygen -R 192.168.250.129`

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
### Docker user, group and groups permissions
```
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
docker run hello-world
# 'reboot' if necessary
```

Install docker if necessary:  
```
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add the repository to Apt sources:
echo \
"deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
"$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt install docker-buildx-plugin
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Move Docker to nova_ssd:
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

### Run jtop in a docker container
Map `/run/jtop.sock` from host to container when starting:  
```
sudo docker run --runtime nvidia -it --rm -v /run/jtop.sock:/run/jtop.sock --network=host dustynv/opencv:4.8.1-r36.2.0
```  

Inside container:  
```
apt install python3-pip
pip install jetson-stats
jtop
```

## Exfat
```
sudo add-apt-repository universe
sudo apt update
sudo apt install exfatprogs
# sudo apt install exfat-fuse
```
