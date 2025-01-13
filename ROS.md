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
