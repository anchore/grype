FROM alpine:3.12.0
RUN wget http://dl-cdn.alpinelinux.org/alpine/v3.9/main/x86_64/libvncserver-0.9.11-r3.apk
RUN apk add  libvncserver-0.9.11-r3.apk
# I know this is cheating a bit...
RUN sed -i 's/V:0.9.11-r3/V:0.9.9-r0/' /lib/apk/db/installed