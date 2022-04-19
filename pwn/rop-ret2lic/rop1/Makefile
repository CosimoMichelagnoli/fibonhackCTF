CC=gcc
CFLAGS=-fno-stack-protector
CONTAINER=rop-compiler:latest

binary:
	$(eval CONTAINER_ID := $(shell docker run -d --rm $(CONTAINER) tail -f /dev/null))
	docker exec -it $(CONTAINER_ID) $(CC) --version
	docker cp ./rop.c $(CONTAINER_ID):/tmp/rop.c
	docker exec -it $(CONTAINER_ID) $(CC) $(CFLAGS) /tmp/rop.c -o /tmp/rop
	docker cp $(CONTAINER_ID):/tmp/rop ./rop
	docker stop $(CONTAINER_ID)

clean:
	rm rop

docker:
	docker build -t rop1 .

remote: docker
	docker run --rm -p "127.0.0.1:22226:22226" -it rop1

extract-libc: docker
	docker rm -f rop1_dummy
	docker create -ti --name rop1_dummy rop1
	docker cp rop1_dummy:/lib/x86_64-linux-gnu/libc-2.31.so ./libc-docker.soh