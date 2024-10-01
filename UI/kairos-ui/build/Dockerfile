FROM node:21-alpine

WORKDIR /usr/src/app

COPY package*.json ./

COPY static/assets/particles.json static/assets/.

RUN npm install --force

COPY . .

RUN npm run build

EXPOSE 8000

ENV NODE_ENV=production

CMD ["npm", "start"]