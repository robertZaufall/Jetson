# Jetson

## Jetson Orin NX

### Fix wifi  
```
sudo apt update && sudo apt upgrade
sudo apt install iwlwifi-modules
```

### Exfat
```
sudo add-apt-repository universe
sudo apt update
sudo apt install exfatprogs
# sudo apt install exfat-fuse
```

### Install tools  
Basic tools  
```
# Chromium (UI)
# Code (terminal)
```
jtop  
```
sudo apt install python3-pip
sudo pip3 install -U jetson-stats
jtop
```

### Remote, login
- auto login (user)
- power settings: don't switch off screen
- delete keyring password (app
- enable remote desktop sharing, vnc
- install xrdp
```
sudo apt install xrdp
```

Docker
```
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
docker run hello-world
# 'reboot' if necessary
```

Nvidia Isaac
```
sudo apt-get install git-lfs
git lfs install --skip-repo
```

```
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
"deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
"$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt install docker-buildx-plugin
```

```
```

```
```

```
```

```
```

```
```

