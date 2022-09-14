FROM ubuntu:20.04

# install 32-bit support
RUN dpkg --add-architecture i386

ENV TZ=America/Los_Angeles

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y tzdata

# general dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y git build-essential python3 python3-pip python3-dev

# install virtualenvwrapper
RUN pip install virtualenvwrapper

# angr dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y openjdk-8-jdk zlib1g:i386 libtinfo5:i386 libstdc++6:i386 libgcc1:i386 libc6:i386 libssl-dev nasm binutils-multiarch qtdeclarative5-dev libpixman-1-dev libglib2.0-dev debian-archive-keyring debootstrap libtool libreadline-dev cmake libffi-dev libxslt1-dev libxml2-dev

# setup user `popkorn` with a home directory
RUN useradd -ms /bin/bash popkorn
USER popkorn
RUN git clone https://github.com/angr/angr-dev.git /home/popkorn/angr-dev

RUN /bin/bash -c "source /usr/local/bin/virtualenvwrapper.sh && \
    cd /home/popkorn/angr-dev && \
    ./setup.sh -e popkorn"

ENV VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3
RUN /bin/bash -c "source /usr/local/bin/virtualenvwrapper.sh && \
    workon popkorn && pip uninstall --yes pyvex && pip install pyvex" # this is a hack to get around a bug in angr-dev

RUN mkdir /home/popkorn/popkorn
COPY ./datasets /home/popkorn/popkorn/datasets/
COPY ./angr_analysis /home/popkorn/popkorn/angr_analysis/
COPY ./evaluation /home/popkorn/popkorn/evaluation/
USER root
RUN chown -R popkorn:popkorn /home/popkorn/popkorn
USER popkorn

RUN echo 'export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3' >> /home/popkorn/.bashrc
RUN echo 'export WORKON_HOME=$HOME/.virtualenvs' >> /home/popkorn/.bashrc
RUN echo 'source /usr/local/bin/virtualenvwrapper.sh && workon popkorn' >> /home/popkorn/.bashrc

WORKDIR /home/popkorn/popkorn
CMD ["/bin/bash"]

