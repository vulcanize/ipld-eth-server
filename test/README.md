
Spin up services: 
```
docker-compose -f docker-compose.test.yml -f docker-compose.yml up -d db dapptools contract eth-server
```

Running unit tests:
```bash
make test_local
```

Running integration test:
```bash
make integrationtest_local
```