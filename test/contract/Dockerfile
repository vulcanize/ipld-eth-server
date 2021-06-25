FROM node:14

ARG ETH_ADDR
ENV ETH_ADDR $ETH_ADDR

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run compile && ls -lah

EXPOSE 3000

ENTRYPOINT ["npm", "start"]