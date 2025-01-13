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

### Remote, login
- auto login (user)
- power settings: don't switch off screen
- delete keyring password (app)
- enable remote desktop sharing, vnc (-> use password!)
- install xrdp (optional)
```
sudo apt install xrdp
```

### SSH
```
sudo apt-get update && sudo apt-get install openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh
```
- put public key(s) to folder `~/.ssh/authorized_keys` for remote connections  
- generate key in `~/.ssh` using `ssh-keygen` or put existing private/pub key pair to connect to visualstudio.com or other sites
- secure copied keys, e.g.: `chmod 600 /home/jetson/.ssh/id_rsa`

### Swapfile
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

### Create nova_ssd for Docker and ROS
```
sudo mkdir -p /mnt/nova_ssd
sudo mount /dev/nvme0n1 /mnt/nova_ssd
sudo chown ${USER}:${USER} /mnt/nova_ssd
```

### Docker
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

## ROS 

### OpenCV
https://qengineering.eu/install-opencv-on-orin-nano.html
```
wget https://github.com/Qengineering/Install-OpenCV-Jetson-Nano/raw/main/OpenCV-4-10-0.sh
sudo chmod 755 ./OpenCV-4-10-0.sh
./OpenCV-4-10-0.sh

# cleanup
rm OpenCV-4-10-0.sh
sudo rm -rf ~/opencv
sudo rm -rf ~/opencv_contrib
```

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
sudo apt install libgtk-3-dev
```

Create ROS Workspace on nova_ssd
```
mkdir -p  /mnt/nova_ssd/workspaces/isaac_ros-dev/src
echo "export ISAAC_ROS_WS=/mnt/nova_ssd/workspaces/isaac_ros-dev/" >> ~/.bashrc
source ~/.bashrc
```

Login ro Nvidia repo and pull first image :
```
docker login nvcr.io
Username: $oauthtoken
Password: MTZ...

docker pull nvcr.io/nvidia/l4t-base:r35.2.1
```

### Nvidia Isaac ROS2 + Orbbec camera:
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
    ros-humble-image-publisher \
    ros-humble-vision-msgs \
    udev \
    libusb-1.0-0 \
    libopenni2-dev \
    && rm -rf /var/lib/apt/lists/*

# Create workspace directory
WORKDIR /workspace

# Copy the entire src directory
COPY src/ src/

# Copy udev rules
RUN ./src/OrbbecSDK_ROS2/orbbec_camera/scripts/install_udev_rules.sh

# Build workspace
RUN . /opt/ros/humble/setup.sh && colcon build --symlink-install

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
sudo docker build -t isaac_ros_orbbec .
```

```
ros2 launch orbbec_camera astra.launch.py \
    color_width:=640 color_height:=480 color_fps:=30 color_format:=RGB888 \
    depth_width:=640 depth_height:=480 depth_fps:=30 depth_format:=Y11
```

### Jetson containers
https://github.com/dusty-nv/jetson-containers  
```
# install the container tools
git clone https://github.com/dusty-nv/jetson-containers
bash jetson-containers/install.sh
```
Local directory get's connected with `jetson-containers`.
Dependecies can be edited in the Dockerfile comments. Versions can be added to `config.py` files.

#### Ollama
https://github.com/dusty-nv/jetson-containers/tree/master/packages/llm/ollama
```
# models cached under jetson-containers/data
jetson-containers run --name ollama $(autotag ollama)
/bin/ollama run mistral

# Open-WebUI Client
docker run -it --rm --network=host --add-host=host.docker.internal:host-gateway ghcr.io/open-webui/open-webui:main
```

#### Faiss
```
CUDA_VERSION=12.6 CUDNN_VERSION=9.3 jetson-containers build faiss
```


## Local Container Registry (macos)

### Add folders
```
mkdir ~/docker/registry
mkdir ~/docker/mirror_docker_io
mkdir ~/docker/mirror_nvcr_io
mkdir ~/docker/certs
mkdir ~/docker/config
```
  
### Add DNS entry to hosts
```
sudo nano /etc/hosts
```
add `127.0.0.1 registry.local` and/or `127.0.0.1 mirror.local` 

### Generate certificate (use newer openssl, to get MACOS compatible certificates)  
```
brew install openssl
cd ~/docker/certs

# openssl req -newkey rsa:4096 -nodes -sha256 -keyout domain.key -x509 -days 3650 -out domain.crt
/opt/homebrew/opt/openssl@3.4/bin/openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout domain.key -out domain.crt \
  -subj "/CN=registry.local" \
  -addext "subjectAltName=DNS:registry.local" \
  -days 3650

sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/docker/certs/domain.crt

# each registry and mirror needs a separate entry (5001: docker.io, 5002: nvcr.io, 5555: registry)
mkdir -p ~/Library/Group\ Containers/group.com.docker/certs.d/registry.local:5001
mkdir -p ~/Library/Group\ Containers/group.com.docker/certs.d/registry.local:5002
mkdir -p ~/Library/Group\ Containers/group.com.docker/certs.d/registry.local:5555
cp domain.crt ~/Library/Group\ Containers/group.com.docker/certs.d/registry.local:5001/ca.crt
cp domain.crt ~/Library/Group\ Containers/group.com.docker/certs.d/registry.local:5002/ca.crt
cp domain.crt ~/Library/Group\ Containers/group.com.docker/certs.d/registry.local:5555/ca.crt
```

### Registry container
create `config_registry.yml` in `~/docker/config`  
```
version: 0.1
log:
  level: debug
  fields:
    service: registry
storage:
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: true
http:
  addr: :5555
  tls:
    certificate: /certs/domain.crt
    key: /certs/domain.key
```

start the container
```
docker run -d \
  --name registry \
  -p 5555:5555 \
  --restart=always \
  -v ~/docker/config/config_registry.yml:/etc/docker/registry/config.yml:ro \
  -v ~/docker/certs/domain.crt:/certs/domain.crt:ro \
  -v ~/docker/certs/domain.key:/certs/domain.key:ro \
  -v ~/docker/registry:/var/lib/registry \
  -e REGISTRY_STORAGE_DELETE_ENABLED=true \
  registry:2
```

### Mirror container
create generic `config_mirror.yml` in `~/docker/config`  
```
version: 0.1
log:
  level: debug
  fields:
    service: registry
storage:
  filesystem:
    rootdirectory: /var/lib/registry
http:
  addr: :5000
  tls:
    certificate: /certs/domain.crt
    key: /certs/domain.key
proxy:
  remoteurl:
```

start the container:  
- for docker.io:
```
docker run -d \
  --name mirror_docker_io \
  -p 5001:5000 \
  --restart=always \
  -v ~/docker/config/config_mirror.yml:/etc/docker/registry/config.yml:ro \
  -v ~/docker/certs/domain.crt:/certs/domain.crt:ro \
  -v ~/docker/certs/domain.key:/certs/domain.key:ro \
  -v ~/docker/mirror_docker_io:/var/lib/registry \
  -e REGISTRY_PROXY_REMOTEURL="https://registry-1.docker.io" \
  registry:2
```

- for nvcr.io (use real username and password):  
```
docker run -d \
  --name mirror_nvcr_io \
  -p 5002:5000 \
  --restart=always \
  -v ~/docker/config/config_mirror.yml:/etc/docker/registry/config.yml:ro \
  -v ~/docker/certs/domain.crt:/certs/domain.crt:ro \
  -v ~/docker/certs/domain.key:/certs/domain.key:ro \
  -v ~/docker/mirror_nvcr_io:/var/lib/registry \
  -e REGISTRY_PROXY_REMOTEURL="https://nvcr.io" \
  -e REGISTRY_PROXY_USERNAME="$oauthtoken" \
  -e REGISTRY_PROXY_PASSWORD="MTZ..." \
  registry:2
```

### Docker on MACOS
Modify daemon.json and restart via UI:  
```
{
  "insecure-registries": [],
  "registry-mirrors": [
    "https://registry.local:5001",
    "https://registry.local:5002"
  ]
}
```

### Test (use "library" for docker.io)
Check website for valid certificate:  
```
cd ~/docker/certs
curl -v --cacert domain.crt https://registry.local:5001/v2/
curl -v --cacert domain.crt https://registry.local:5002/v2/
curl -v --cacert domain.crt https://registry.local:5555/v2/
```

Pull/push test images:  
```
docker pull registry.local:5001/library/hello-world:latest
docker pull registry.local:5002/nvidia/l4t-base:r36.2.0

docker tag hello-world registry.local:5555/hello-world
docker push registry.local:5555/hello-world

docker pull registry.local:5555/hello-world
```

### Jetson
Copy crt file e.g. to git folder by using VSCode Remote and register ca cert for each endpoint:
```
sudo mkdir -p /etc/docker/certs.d/registry.local:5001
sudo mkdir -p /etc/docker/certs.d/registry.local:5002
sudo mkdir -p /etc/docker/certs.d/registry.local:5555
sudo cp domain.crt /etc/docker/certs.d/registry.local:5001/ca.crt
sudo cp domain.crt /etc/docker/certs.d/registry.local:5002/ca.crt
sudo cp domain.crt /etc/docker/certs.d/registry.local:5555/ca.crt
sudo chmod 644 /etc/docker/certs.d/registry.local:5001/ca.crt
sudo chmod 644 /etc/docker/certs.d/registry.local:5002/ca.crt
sudo chmod 644 /etc/docker/certs.d/registry.local:5555/ca.crt

sudo nano /etc/docker/daemon.json
sudo systemctl restart docker
```

Modify `daemon.json` content:
```
{
    "runtimes": {
        "nvidia": {
            "path": "nvidia-container-runtime",
            "runtimeArgs": []
        }
    },
    "default-runtime": "nvidia",
    "data-root": "/mnt/nova_ssd/docker",
    "registry-mirrors": [
        "https://registry.local:5001",
        "https://registry.local:5002"
    ]
}
```

Remark:  
Only `docker.io` images are cached by the proxy automatically.
`nvcr.io` images for example have to be loaded using `registry.local:5002/nvidia/<image>:<tag>` and are then getting cached.  

Push locally built images to registry:  
```
docker tag abc registry.local:5555/abc
docker push registry.local:5555/abc:latest

docker tag faiss:r36.4.0-cu126 registry.local:5001/faiss:r36.4.0-cu126
docker push registry.local:5001/faiss:r36.4.0-cu126
```
