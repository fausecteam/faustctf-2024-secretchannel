FROM faust.cs.fau.de:5000/secretchannel_deps as build

COPY src/ /srv/secretchannel/

# Pull dependencies if necessary
# This step should not be necessary in the ctf
# We provide the node_modules bundled in case your VM does not have internet access
RUN cd srv/secretchannel; [ -d node_modules ] || npm install

RUN cd /srv/secretchannel && tsc


FROM node:22-alpine

RUN mkdir -p /srv/secretchannel /upload
COPY --from=build /srv/secretchannel/*.js /srv/secretchannel/
COPY --from=build /srv/secretchannel/package.json /srv/secretchannel/
COPY --from=build /srv/secretchannel/views/ /srv/secretchannel/views/
COPY --from=build /srv/secretchannel/public/ /srv/secretchannel/public/

COPY --from=build /srv/secretchannel/node_modules /srv/secretchannel/node_modules

CMD cd /srv/secretchannel && node server.js
