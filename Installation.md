# Jetson Orin NX

## Yahboom Orin NX Wi-Fi

The Yahboom Orin NX carrier used here has an Intel 8265 / 8275 Wi-Fi card. JetPack 7.2 ships the `6.8.12-1021-tegra` kernel without `iwlwifi`, so the Orin NX flash helper patches cached, prebuilt Intel Wi-Fi modules into the NX rootfs before flashing.

The cached assets live under:

```text
src/assets/yahboom_orin_nx_wifi/6.8.12-1021-tegra/
```

`src/orin_nx.sh` applies those assets automatically by default and runs `depmod` in the target rootfs. Before copying files, it verifies that the cached asset directory matches the target rootfs kernel, validates the cached module `vermagic`, and checks `SHA256SUMS`.

If the cached assets do not match the image kernel, the script continues flashing and bakes a manual target-side repair script into the image:

```text
~/yahboom-orin-nx-wifi-fix.sh
/usr/local/sbin/yahboom-orin-nx-wifi-fix.sh
```

Run it on the Jetson after first boot if the prebuilt modules were skipped:

```bash
~/yahboom-orin-nx-wifi-fix.sh
sudo reboot
```

`src/orin_nano.sh` does not apply this patch and uses its separate Orin Nano SDK rootfs. To skip the NX Wi-Fi patch explicitly:

```bash
bash src/orin_nx.sh <user> <pass> <hostname> --skip-intel-wifi-fix
```

See [Yahboom Orin NX Wi-Fi Fix](yahboom_orin_nx_wifi_fix.md) for the post-flash DKMS build, firmware details, and the cached-asset flashing flow.

## Rename device
```
sudo hostnamectl set-hostname NEWNAME
sudo sed -i "s/^\(127\.0\.1\.1\s*\).*/\1NEWNAME/" /etc/hosts
```

## Install tools  

See also https://github.com/jetsonhacks/jetson-orin-setup

### Basic tools
Basic tools installation
```
sudo apt install nano btop curl git-lfs -y
# usage: git lfs install
```

### jtop
jtop installation
```
sudo apt install python3-pip -y

# new
sudo pip3 install -U pip setuptools wheel
sudo pip3 install --upgrade --force-reinstall git+https://github.com/rbonghi/jetson_stats.git
sudo jtop --install-service

# old
sudo pip3 install -U jetson-stats
sudo systemctl restart jtop.service
```

If "jetpack" is found missing or jtop outdated, the version numbers can be added manually at   
`/usr/local/lib/python3.10/dist-packages/jtop/core/jetson_variables.py` by adding the line  
`"36.4.4": "6.2.1",` and a restart  
```
sudo systemctl restart jtop.service
jtop
```

## Remote, login
- auto login (user)
- delete keyring password (app), set empty password
- enable remote desktop sharing, vnc (-> use password!)
- power settings: don't switch off screen

## SSH
- put public key(s) to folder `~/.ssh/authorized_keys` for remote connections  
- generate key in `~/.ssh` using `ssh-keygen` or put existing private/pub key pair to connect to visualstudio.com or other sites
- secure copied keys, e.g.: `chmod 600 /home/jetson/.ssh/id_rsa`
- ractivate ssh (e.g. VSCode)   
```
ssh-keygen -R 192.168.250.x
ssh -o StrictHostKeyChecking=accept-new <user>@192.168.250.x
```

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
sudo apt update
sudo apt install ca-certificates curl gnupg -y
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add the repository to Apt sources:
echo \
"deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
"$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update

sudo apt install docker-buildx-plugin -y
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
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
apt install python3-pip -y
pip install jetson-stats
jtop
```

## Headless mode
Just now:  
```
sudo init 3 # headless
sudo init 5 # ui active
```
Permanent:  
```
sudo systemctl set-default multi-user.target # headless mode permanent
sudo systemctl set-default graphical.target  # deactivate permanent headless mode
```
## Exfat
```
sudo add-apt-repository universe
sudo apt update
sudo apt install exfatprogs -y
# sudo apt install exfat-fuse -y
```
