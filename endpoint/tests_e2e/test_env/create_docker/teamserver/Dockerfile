ARG TEAMSERVER_VERSION=1.60

FROM dev.privmx.com:5050/teamserverdev/privmx-server-ee:${TEAMSERVER_VERSION}

COPY storage.tar.gz .
RUN tar -xvf storage.tar.gz -C / && rm -f storage.tar.gz
