# syntax=docker/dockerfile:1

FROM node:24.20.0-alpine3.24 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:24.20.0-alpine3.24 AS builder
WORKDIR /app
ARG UI_VERSION=dev
ENV NEXT_TELEMETRY_DISABLED=1
ENV NEXT_PUBLIC_UI_VERSION=$UI_VERSION
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:24.20.0-alpine3.24 AS runner
WORKDIR /app
ARG UI_VERSION=dev
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV NEXT_PUBLIC_UI_VERSION=$UI_VERSION
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

RUN apk upgrade --no-cache zlib libcrypto3 libssl3 && \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

# Next.js "standalone" output (see next.config.ts)
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 3000
CMD ["node", "server.js"]
