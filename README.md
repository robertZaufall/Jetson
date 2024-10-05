# Jetson

## Jetson Orin NX

### Fix wifi  
```
sudo apt update && sudo apt upgrade
sudo apt install iwlwifi-modules
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

