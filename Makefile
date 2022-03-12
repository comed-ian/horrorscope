build: Dockerfile
	docker build . -t ubuntu:21.10

rebuild: Dockerfile
	docker rmi -f $$(echo $$(docker images | grep ubuntu | head -1 | awk '{print $$3}'))
	docker build . -t ubuntu:21.10

run:
	docker run -it ubuntu:21.10 bash
mount:
	docker run -it -v $(PWD):/tmp ubuntu:21.10 bash 

attach:
	docker exec -it $$(echo $$(docker ps -q | head -1)) bash

