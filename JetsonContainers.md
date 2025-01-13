# Jetson containers
https://github.com/dusty-nv/jetson-containers  
```
# install the container tools
git clone https://github.com/dusty-nv/jetson-containers
bash jetson-containers/install.sh
```
Local directory get's connected with `jetson-containers`.
Dependecies can be edited in the Dockerfile comments. Versions can be added to `config.py` files.

## Ollama
https://github.com/dusty-nv/jetson-containers/tree/master/packages/llm/ollama
```
# models cached under jetson-containers/data
jetson-containers run --name ollama $(autotag ollama)
/bin/ollama run mistral

# Open-WebUI Client
docker run -it --rm --network=host --add-host=host.docker.internal:host-gateway ghcr.io/open-webui/open-webui:main
```

## Faiss
```
CUDA_VERSION=12.6 CUDNN_VERSION=9.3 jetson-containers build faiss
```
