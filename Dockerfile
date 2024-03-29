FROM node:20-alpine

RUN apk add nmap

RUN mkdir -p /opt/app
WORKDIR /opt/app
COPY package.json package-lock.json .
RUN npm install
COPY . .
EXPOSE 3000
CMD [ "npm", "start"]