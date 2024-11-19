ARG TEAMSERVER_VERSION=1.0.1

FROM simplito/privmx-bridge:${TEAMSERVER_VERSION}

COPY storage.tar.gz .
RUN tar -xvf storage.tar.gz -C / && rm -f storage.tar.gz
