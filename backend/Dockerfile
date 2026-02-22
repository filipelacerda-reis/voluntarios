FROM node:20-alpine

WORKDIR /app

COPY backend/package.json ./package.json
RUN npm install --omit=dev

COPY backend/src ./src
COPY backend/scripts ./scripts
COPY frontend ./public

EXPOSE 8080

CMD ["node", "src/server.js"]
