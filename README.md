# Jetson

## Jetson Orin NX

Install tools  
```
# Chromium (UI)
# Code (terminal)
```

Fix wifi  
```
sudo apt update && sudo apt upgrade
sudo apt install iwlwifi-modules
```

Install jtop  
```
sudo apt install python3-pip
sudo pip3 install -U jetson-stats
jtop
```

Docker
```
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
docker run hello-world
# 'reboot' if necessary
```

