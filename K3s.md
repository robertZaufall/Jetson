# K3s on Jetson

[How to run Cluster Management Software K3s on NVIDIA Jetson?](https://www.seeedstudio.com/blog/2021/01/22/how-to-run-cluster-management-software-k3s-on-nvidia-jetson) (2021)  
[Step-by-Step Guide: Installing Kubernetes on Jetson nano](https://medium.com/@jpraveenkanna/step-by-step-guide-installing-kubernetes-on-a-jetson-nano-67da8fa183f8) (2023)  
[How to Install Kubernetes Using K3s On Ubuntu 22.04](https://www.linuxtechi.com/install-kubernetes-using-k3s-on-ubuntu/) (2024)  
[Triton Inference Server on Nvidia Jetson using K3s and MinIO](https://www.hackster.io/shahizat/triton-inference-server-on-nvidia-jetson-using-k3s-and-minio-cbcfe3) (2024)  

## Prerequisites

- update package repo
```
sudo apt update
sudo apt install curl wget -y
```

- deactivate IPv6
```
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=1
```

## Installation

```
mkdir $HOME/.kube/
curl -sfL https://get.k3s.io | sh -s - --docker --write-kubeconfig-mode 644 --write-kubeconfig $HOME/.kube/config
sudo systemctl status k3s
sudo kubectl cluster-info
kubectl get nodes
```

## Test

- create deployment manifest file `nano test_k3s.yaml`  
```
apiVersion: v1
kind: Pod
metadata:
  name: torch
spec:
  containers:
  - name: torchtest
    image: dustynv/l4t-pytorch:r36.2.0
    securityContext:
      privileged: true
    command: [ "/bin/bash", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
```

- start deployment    
```
kubectl apply -f test_k3s.yaml
sudo kubectl cluster-info
```

- start console to pod  
```
kubectl exec -it torch -- python3
```

- check for GPU access  
```
import torch
torch.cuda.is_available()
torch.cuda.device_count()
torch.cuda.current_device()
torch.cuda.get_device_name(0)
```

## Uninstallation
```
kubectl delete pod torch
sudo /usr/local/bin/k3s-uninstall.sh
```
