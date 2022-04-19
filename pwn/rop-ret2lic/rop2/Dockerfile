FROM ubuntu:20.04
RUN apt-get -y update
RUN apt-get -y install xinetd

RUN groupadd -g 1000 challenge && useradd -g challenge -m -u 1000 challenge -s /bin/bash

ADD rop /rop
ADD xinetd.conf /etc/xinetd.d/sum


RUN chmod +x /rop

CMD xinetd -d -dontfork
