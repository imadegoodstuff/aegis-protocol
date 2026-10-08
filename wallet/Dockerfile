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
COPY public ./public
ARG VITE_BUILD_SHA=dev
ENV VITE_BUILD_SHA=$VITE_BUILD_SHA
RUN npx vite build

### Runtime: tiny static server on port 8080 with serve.json headers
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN npm install -g serve@14 --no-audit --no-fund
COPY --from=build /app/dist ./
COPY serve.json ./
EXPOSE 8080
# -s = SPA fallback is handled by rewrites in serve.json; we drop -s so headers apply
CMD ["serve", "-l", "tcp://0.0.0.0:8080", "-c", "serve.json", "."]
