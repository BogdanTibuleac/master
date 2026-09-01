# syntax=docker/dockerfile:1.7
FROM node:22-bookworm-slim AS build

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend ./
ARG NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
RUN npm run build

FROM node:22-bookworm-slim

WORKDIR /app
ENV NODE_ENV=production
COPY --chown=node:node --from=build /app ./

USER node
EXPOSE 3000
CMD ["npm", "run", "start", "--", "--ip", "0.0.0.0", "--port", "3000"]
