# STIG Log Analysis POC

## Update env
    1. Update .env-template file as appropriate
    2. Rename .env-template to .env
    3. Run
    ```
    source .env
    cp .env api/.env
    ```

## Deploy Custom vLLM Runtime

```
oc apply -f resources/custom-vllm-serving-runtime/custom-vllm.yaml
```

## Deploy local LLMs
Granite 4 Tiny:
```
oc apply -f resources/custom-vllm-serving-runtime/custom-vllm.yaml

Use the following settings:
python -m vllm.entrypoints.openai.api_server \
--model ibm-granite/granite-4.0-h-tiny \
--port 8000 \
--dtype bfloat16 \
--max-model-len 128000 \
--trust-remote-code \
--gpu-memory-utilization 0.9
```

## Setup N8N on RHEL (NOTE: convert to production-grade)
```
mkdir n8n  && cd n8n
sudo yum install -y nodejs
sudo dnf module enable nodejs:20 -y    
sudo dnf install nodejs -y
mkdir ~/.n8n
cat > /.env << EOF
N8N_BASIC_AUTH_ACTIVE=true
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=demo123
N8N_HOST=localhost
N8N_PORT=5678
N8N_PROTOCOL=http
GENERIC_TIMEZONE=UTC
N8N_SECURE_COOKIE=false
EOF
sudo npm install -g pm2
pm2 start n8n --name n8n
pm2 save
```

## RUN RAG API locally (without Podman)
```
pip install -r requirements.txt
cd api
uvicorn stigservice:app --reload
# View Swagger at http://<hostname>:8000/docs
```

## Run RAG API via Podman
Run the API via Podman:
```
source .env
podman build -t stig-service:latest .
podman run --env-file .env --publish 8080:8080 stig-service:latest
# View Swagger at http://<hostname>:8080/docs
```

## Run RAG API on Openshift
```
oc new-project stig-service
oc new-build --name=stig-api --strategy=docker --binary
cp Containerfile Dockerfile
oc start-build stig-api --from-dir . --follow

# OR

source .env
podman login -u ${DOCKER_USERNAME}${DOCKER_USERNAME_SUFFIX} -p ${DOCKER_PASSWORD} ${DOCKER_HOST}
podman build -t quay.io/oawofolurh/stig-api:latest .
podman push quay.io/oawofolurh/stig-api:latest
oc expose deploy stig-api --port 8000
oc expose svc stig-api
```

## Run RAG API on RHEL (NOTE: convert to production-grade)
```
sudo dnf update -y
sudo dnf install python3 git -y
git clone https://github.com/agapebondservant/dlagency.git
cd dlagency/api
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
uvicorn stigservice:app --reload --host 0.0.0.0 --port 8000
```

## Other
1. Sample Github repository GitHub repository containing a dataset for assessing a web server's compliance with national cybersecurity agency requirements related to Transport Layer Security (TLS)
https://zenodo.org/records/15011611
