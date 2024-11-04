FROM dev.privmx.com:5050/teamserverdev/privmx-server-ee/mongo-with-rs2:7

# COPY data.tar.gz /
# RUN tar -xvf /data.tar.gz -C /

COPY dump.tar.gz /
RUN tar -xvf /dump.tar.gz -C /
# COPY restore.sh /
# RUN chmod +x /restore.sh



