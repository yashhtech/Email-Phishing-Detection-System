# Frontend Dockerfile — Email Threat Detection Platform

# ──────────────────────────────────────────────
# Stage 1: Development (Vite dev server)
# ──────────────────────────────────────────────
FROM node:22-alpine AS development

# Security: non-root user
RUN addgroup --gid 1000 appgroup && \
    adduser --uid 1000 --ingroup appgroup --shell /bin/sh --disabled-password appuser

WORKDIR /app

# Copy package files first for layer cache
COPY package*.json ./

RUN npm ci

COPY . .

USER appuser

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# ──────────────────────────────────────────────
# Stage 2: Builder (production build)
# ──────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Build args for env vars baked into the bundle
ARG VITE_API_BASE_URL
ARG VITE_WS_URL
ARG VITE_APP_ENV=production

RUN npm run build

# ──────────────────────────────────────────────
# Stage 3: Production (Nginx, minimal)
# ──────────────────────────────────────────────
FROM nginx:alpine AS production

# Remove default nginx static assets
RUN rm -rf /usr/share/nginx/html/*

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy Nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Security: non-root nginx
RUN addgroup --gid 1001 nginxgroup && \
    adduser --uid 1001 --ingroup nginxgroup --shell /bin/sh --disabled-password nginxuser && \
    chown -R nginxuser:nginxgroup /usr/share/nginx/html && \
    chown -R nginxuser:nginxgroup /var/cache/nginx && \
    chown -R nginxuser:nginxgroup /var/log/nginx && \
    touch /var/run/nginx.pid && \
    chown nginxuser:nginxgroup /var/run/nginx.pid

USER nginxuser

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -q --spider http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
