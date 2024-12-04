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

### Docker
```
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
docker run hello-world
# 'reboot' if necessary
```

### Share folder in Filemanager
Share folder via UI.  

### Setup remote SSH
Local device  
```
ssh-keygen
```

Install VS Code Remote-SSH extension
Connect to Ubuntu.

### Nvidia Isaac
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
sudo chown ${USER}:${USER} /mnt/nova_ssd
sudo systemctl stop docker
sudo du -csh /var/lib/docker/ && \
    sudo mkdir /mnt/nova_ssd/docker && \
    sudo rsync -axPS /var/lib/docker/ /mnt/nova_ssd/docker/ && \
    sudo du -csh  /mnt/nova_ssd/docker/
```

```
mkdir -p  /mnt/nova_ssd/workspaces/isaac_ros-dev/src
echo "export ISAAC_ROS_WS=/mnt/nova_ssd/workspaces/isaac_ros-dev/" >> ~/.bashrc
source ~/.bashrc
```

Edit daemon.json
```
sudo apt install nano
sudo vi /etc/docker/daemon.json
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

```
sudo mv /var/lib/docker /var/lib/docker.old
sudo systemctl daemon-reload && \
    sudo systemctl restart docker && \
    sudo journalctl -u docker
docker pull nvcr.io/nvidia/l4t-base:r35.2.1
```

```
sudo apt install libgtk-3-dev
cd /usr/src/jetson_multimedia_api/argus/cmake/
sudo cmake ..
sudo make install
argus_syncstereo # error
```

Next try:
```
mkdir -p ~/workspaces/isaac_ros-dev/src
cd ~/workspaces/isaac_ros-dev/src
git clone https://github.com/NVIDIA-ISAAC-ROS/isaac_ros_common
git clone https://github.com/orbbec/OrbbecSDK_ROS2.git
cd ..
```

```
cd ~/workspaces/isaac_ros-dev
cat << EOF > Dockerfile
FROM nvcr.io/nvidia/isaac/ros:aarch64-ros2_humble_5d698e0d23e98e2567b1c9b70abd0c1f

# Install additional dependencies
RUN apt-get update && apt-get install -y \
    ros-humble-cv-bridge \
    ros-humble-image-transport \
    ros-humble-image-pipeline \
    ros-humble-vision-msgs \
    udev \
    libusb-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Create workspace directory
WORKDIR /workspace

# Copy the entire src directory
COPY src/ src/

# Build ROS workspace
WORKDIR /workspace
RUN . /opt/ros/humble/setup.sh \
    && colcon build --symlink-install

# Source setup in bashrc
RUN echo "source /workspace/install/setup.bash" >> /root/.bashrc

WORKDIR /workspace
EOF
```

```
cat << EOF > launch_container.sh
#!/bin/bash
sudo docker run --rm -it \
    --network host \
    --privileged \
    --runtime nvidia \
    -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix/:/tmp/.X11-unix \
    -v /dev:/dev \
    --device-cgroup-rule='c 189:* rmw' \
    isaac_ros_orbbec \
    bash
EOF

chmod +x launch_container.sh
```

```
sudo tee /etc/udev/rules.d/99-orbbec-camera.rules << EOF
SUBSYSTEM=="usb", ATTR{idVendor}=="2bc5", MODE:="0666", GROUP:="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="2bc5", ATTR{idProduct}=="0401", MODE:="0666", GROUP:="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="2bc5", ATTR{idProduct}=="0402", MODE:="0666", GROUP:="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="2bc5", ATTR{idProduct}=="0403", MODE:="0666", GROUP:="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="2bc5", ATTR{idProduct}=="0404", MODE:="0666", GROUP:="plugdev"
EOF

sudo udevadm control --reload-rules && sudo udevadm trigger
```

```
docker login nvcr.io
Username: $oauthtoken
Password: MTZ...

sudo docker build -t isaac_ros_orbbec .
```


```
```


```
```


```
```


```
```

