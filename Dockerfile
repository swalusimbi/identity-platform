# Build stage: full toolchain so native modules (argon2) always compile
FROM node:24-alpine AS build
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

# Runtime: only what the platform needs to serve
FROM node:24-alpine
# openssl generates a dev signing key pair on first boot when none is configured
RUN apk add --no-cache openssl
WORKDIR /app
ENV NODE_ENV=development
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY drizzle ./drizzle
COPY public ./public
COPY docs/openapi.json ./docs/openapi.json
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 5300
ENTRYPOINT ["/entrypoint.sh"]
