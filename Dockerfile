FROM debian:stable-slim

ARG DEBIAN_FRONTEND=noninteractive

LABEL MAINTAINER Nico <nik0chan@hotmail.com>

WORKDIR /root

RUN apt-get update                                                                                                             && \
    apt install -y wget gpg git                                                                                                && \
    wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add -                                             && \
    echo "deb http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list                 && \
    apt-get update                                                                                                             && \
    apt install -y python3 python3-pip unzip libnss3 libnspr4 libxcb1 git libglib2.0-0 libdbus-1-3 google-chrome-stable        && \  
    git clone https://github.com/nik0chan/get_assets.git                                                                       && \ 
    chmod +x $HOME/get_assets/get_assets.py                                                                                    && \
    mkdir /var/lib/dpkg/alternatives -p                                                                                        && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3 0                                                    && \
    python -m pip install dnspython requests selenium                                                                          && \
    CHROMEDRIVER=$(wget -qO- https://chromedriver.storage.googleapis.com/LATEST_RELEASE)                                       && \
    wget https://chromedriver.storage.googleapis.com/$CHROMEDRIVER/chromedriver_linux64.zip -O /usr/local/bin/chromedriver.zip && \
    unzip /usr/local/bin/chromedriver.zip -d /usr/local/bin                                                                    && \   
    chmod 755 /usr/local/bin/chromedriver                                                                                      && \
    rm -rf /var/lib/apt /var/lib/dpkg /var/cache/apt /usr/share/doc /usr/share/man /usr/share/info                             && \
    rm -f /usr/local/bin/chromedriver.zip                                                                                       
VOLUME /reports

WORKDIR /reports