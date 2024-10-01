
DC = docker compose

.PHONY: build deploy build-redeploy

build:
	docker build -f build/Dockerfile . -t recontech404/kairos-server:v1

deploy:
	$(DC) -f build/docker-compose.yml up -d

clean:
	$(DC) -f build/docker-compose.yml down

build-redeploy: build deploy