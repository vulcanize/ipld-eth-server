docker-compose -f docker-compose.test.yml -f docker-compose.yml up -d db
PGPASSWORD=password DATABASE_USER=vdbm DATABASE_PORT=8077 DATABASE_PASSWORD=password DATABASE_HOSTNAME=127.0.0.1 make test