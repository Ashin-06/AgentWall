# Development server for the dashboard (vite). Production serves dashboard/dist from the main image.
FROM node:22-alpine

ENV CYPRESS_INSTALL_BINARY=0
WORKDIR /app
RUN chown node:node /app
USER node

COPY --chown=node:node package*.json ./
RUN npm ci

COPY --chown=node:node . .

EXPOSE 3000

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
