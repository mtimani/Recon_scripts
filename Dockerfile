FROM debian:12

ENV DEBIAN_FRONTEND noninteractive

RUN echo "LC_ALL=en_US.UTF-8" >> /etc/environment
RUN echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
RUN echo "LANG=en_US.UTF-8" > /etc/locale.conf

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y locales zsh lsb-release wget curl tar git sed sudo
RUN locale-gen en_US.UTF-8

RUN mkdir /setup

RUN mkdir -p /home/user/

COPY *.py /setup/
COPY setup.sh /setup/

RUN chmod +x /setup/setup.sh

# RUN /setup/setup.sh
RUN cd /setup && ./setup.sh

RUN apt clean -y && apt autoclean -y

WORKDIR /data
