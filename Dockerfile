FROM node:18

WORKDIR /app

COPY . .

RUN chmod +x stockfish

RUN npm install

CMD ["node", "server.js"]
