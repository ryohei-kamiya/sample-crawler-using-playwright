FROM mcr.microsoft.com/playwright/python:jammy
RUN apt-get update && apt-get -y upgrade && apt-get -y install language-pack-ja

ENV TZ=Asia/Tokyo
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
ENV PYTHONIOENCODING=utf-8
ENV LC_ALL='ja_JP.UTF-8'
ENV LANG='ja_JP.UTF-8'
ENV USER crawler
ENV PYENV_ROOT /home/${USER}/.pyenv

ARG UID=1234
RUN useradd -u ${UID} -m ${USER}

COPY ./crawler/requirements.txt /home/${USER}/requirements.txt
RUN apt-get -y install python3-pip python3-venv python3-seccomp libseccomp-dev strace && \
  pip3 install --upgrade pip && \
  pip3 install -r /home/${USER}/requirements.txt

COPY ./crawler /home/${USER}
RUN chown -R ${USER}:${USER} /home/${USER}

WORKDIR /home/${USER}
USER ${USER}
