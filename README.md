# STIG Log Analysis POC

## RUN RAG API locally (without Podman)
```
pip install -r fastapi[standard]
cd api
uvicorn stigservice:app --reload
# View Swagger at http://<hostname>:8000/docs
# Query API should be available at http://<hostname>:8000/stigs/query
```

## Run RAG API via Podman
Run the API via Podman:
```
podman build -t stig-service:latest .
podman run --env-file .env --publish 8080:8080 stig-service:latest
# View Swagger at http://<hostname>:8080/docs
# Query API should be available at http://<hostname>:8080/stigs/query
```

## Run RAG API on Openshift
```
oc new-project stig-service
oc new-build --name=stig-api --strategy=docker --binary
oc start-build stig-api --from-dir docker --follow
```

## Other
1. Sample Github repository GitHub repository containing a dataset for assessing a web server's compliance with national cybersecurity agency requirements related to Transport Layer Security (TLS)
https://zenodo.org/records/15011611
