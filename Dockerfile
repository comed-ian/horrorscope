FROM ubuntu:21.10
RUN apt-get update && apt-get -y upgrade
RUN apt install python3 -y
RUN apt install vim -y
RUN apt install python3-pip -y
RUN pip3 install pwntools

COPY ./horrorscope /tmp
COPY ./flag.txt /tmp
COPY ./cookies.txt /tmp
COPY ./oracle.txt /tmp
COPY ./exploit.py /tmp

RUN chmod 775 /tmp/horrorscope