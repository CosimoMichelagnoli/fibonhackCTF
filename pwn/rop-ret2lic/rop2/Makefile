CC=gcc
CFLAGS=
CONTAINER=rop-compiler:latest

binary:
	$(eval CONTAINER_ID := $(shell docker run -d --rm $(CONTAINER) tail -f /dev/null))
	docker cp ./rop.c $(CONTAINER_ID):/tmp/rop.c
	docker exec -it $(CONTAINER_ID) $(CC) $(CFLAGS) /tmp/rop.c -o /tmp/rop
	docker cp $(CONTAINER_ID):/tmp/rop ./rop
	docker stop $(CONTAINER_ID)

clean:
	rm rop

docker:
	docker build -t rop2 .

remote: docker
	docker run --rm -p "127.0.0.1:22226:22226" -it rop2

extract-libc: docker
	docker rm -f rop2_dummy
	docker create -ti --name rop2_dummy rop2
	docker cp rop2_dummy:/lib/x86_64-linux-gnu/libc-2.31.so ./libc-docker.so