# A diferencia de agente-concursos, este servicio no necesita Playwright --
# alcanza con una imagen simple de Node. node:sqlite (usado en src/db.js) es
# una API experimental disponible desde Node 22.5; 22-slim ya la trae.
FROM node:22-slim

WORKDIR /app

# Instalar dependencias primero (aprovecha el cache de Docker si el codigo
# cambia pero package.json no).
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# Copiar el resto del codigo.
COPY . .

# Railway inyecta PORT automaticamente; server.js ya lo lee de process.env.PORT.
EXPOSE 3300

# IMPORTANTE (ver checklist de despliegue en bitacora-agente-concursos.md,
# entrada de la Fase E): antes del primer arranque en Railway hay que correr
# "npm run seed" una vez contra el volumen persistente (PERSIST_DIR), o el
# primer intento de login va a fallar porque la tabla usuarios está vacía.
CMD ["node", "src/server.js"]
