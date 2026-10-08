### Builder
FROM node:22-alpine AS build
WORKDIR /app
# install deps (cached layer)
COPY package.json package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm \
    (npm ci --no-audit --no-fund || npm install --no-audit --no-fund)
# build
COPY tsconfig.json vite.config.ts index.html ./
COPY src ./src
RUN npx vite build

### Runtime: tiny static server on port 8080
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN npm install -g serve@14 --no-audit --no-fund
COPY --from=build /app/dist ./dist
EXPOSE 8080
CMD ["serve", "-s", "dist", "-l", "tcp://0.0.0.0:8080"]
