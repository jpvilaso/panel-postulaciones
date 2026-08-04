# Panel de Postulaciones — Fase 3 (prototipo funcional)

Prototipo **real y corriendo** (no un mockup estático) de la Fase 3 del Agente de
Concursos: login individual por rol, navegación directa sin portada intermedia,
tracking de postulaciones con semáforo calculado (nunca a mano), generación de
anexos y auditoría de documentos con IA, panel del equipo (kanban) y panel del
director (Opsroom). Implementa las Partes 1, 3, 3.5, 3.6, 4 y 4.5 de
`../plan-implementacion.md` — Parte 2 (extracción real de la matriz desde el PDF
de las bases) y Parte 5 (resumen ejecutivo + redacción asistida) quedan fuera de
este prototipo, ver "Qué falta" más abajo.

## Cómo correrlo

```bash
npm install        # si no vienen ya los node_modules
npm run seed        # crea data/panel.db y lo llena de datos reales + sintéticos
npm start           # http://localhost:3300
```

Abre `http://localhost:3300` — te manda a `/login.html` si no hay sesión.

**Usuarios de demo** (clave `concursos2026` para todos):

| Correo | Rol | Aterriza en |
|---|---|---|
| mrojas@ceodoc.cl | equipo | Mis postulaciones |
| jsoto@ceodoc.cl | equipo | Mis postulaciones |
| pdiaz@ceodoc.cl | equipo | Mis postulaciones |
| directora@fundacion.cl | director | Panel del director |

## De dónde salen los datos

- **8 convocatorias reales**, tomadas de `../agente-concursos/data/memoria.json`
  (el mismo archivo que usa el monitoreo ya en producción) — fechas de cierre,
  títulos, links y categorías reales de CORFO, Cultura y Mercado Público. El
  semáforo de cada una se calcula de verdad contra la fecha de hoy, así que la
  mezcla de verde/ámbar/rojo que ves cambia según cuándo corras la demo.
- **1 postulación completa real**: FFOP 2026 / Fundación Sewell (`caso-piloto-
  FFOP-2026/`), con el checklist de documentos real, incluida la auditoría que
  detecta el error real que le costó $4.000.000 (contrato de prestación de
  servicios vencido + F29 faltante del prevencionista Rodrigo Orellana).
- **Datos sintéticos** donde el dato real no existe porque es información
  interna (no pública): responsables asignados, checklist genérico de las
  otras 8 postulaciones, notificaciones, log de eventos.

Corre `npm run seed` de nuevo en cualquier momento para reiniciar todo desde cero.

## Modo IA: real vs. demo

Los 2 endpoints de IA de este prototipo (`/api/documentos/:id/generar-anexo` y
`/api/documentos/:id/auditar`) llaman de verdad a la API de Claude si defines
`ANTHROPIC_API_KEY` en un archivo `.env` (copia `.env.example`). Sin la key,
siguen funcionando — generan un resultado sintético, determinístico, armado
con los datos reales que ya existen en la postulación (nunca al azar), y lo
marcan explícitamente como "modo demo" en la respuesta y en la pantalla, para
que nunca se confunda con un resultado real.

## Qué es real y funcional (no maqueta)

- Login con sesión y contraseña con hash (`bcryptjs`), dos roles.
- Base de datos SQLite real (`node:sqlite`, nativo de Node 22, sin dependencias
  compiladas) con las 7 tablas de `arquitectura-panel-control.md` sección 2.
- Semáforo (`src/semaforo.js`) calculado con la fecha real del sistema —  no es
  un valor guardado a mano en el seed.
- Las acciones de los botones (marcar reunido, generar anexo, aprobar anexo,
  registrar firma externa, auditar) escriben de verdad en la base de datos y
  quedan en `log_eventos` — recargar la página muestra el estado actualizado.
- **Descarga real de anexos generados**: "Generar borrador (IA)" arma el texto
  y "Descargar borrador (.docx)" lo entrega como un Word real (`src/docgen.js`,
  librería `docx`, sin dependencias nativas) — para editarlo o mandarlo a
  firmar fuera del sistema.
- **Carga real de archivos**: cualquier documento (externo o anexo) se puede
  reunir subiendo el archivo de verdad (`multer`, guardado en
  `data/uploads/`, servido solo con sesión iniciada). Si el documento requiere
  firma externa, subir el archivo firmado es lo que lo marca "reunido" — no
  hay un botón que lo declare reunido sin adjuntar nada.
- Panel del director: conteo verde/ámbar/rojo, atención inmediata, puntos de
  atención, KPIs, embudo por etapa y look-ahead a 3 semanas, todos calculados
  desde los datos reales de la base, no hardcodeados.

## El flujo completo de un anexo (generar → descargar → firmar/editar → subir → auditar)

1. En la pestaña **Documentos** de una postulación, click **"Generar borrador
   (IA)"** — llena la plantilla con los datos reales ya cargados.
2. Click **"Descargar borrador (.docx)"** — se baja un Word real, editable.
3. Edítalo o hazlo firmar fuera del sistema (ej. el director regional del
   Serpat, en el caso real del Anexo N°1).
4. Vuelve a la misma fila y usa el selector de archivo para **subir la
   versión final** — eso es lo que marca el documento "reunido" (o, si pedía
   firma externa, lo que registra la firma). Si prefieres aceptar el borrador
   de la IA tal cual, "Aprobar borrador (sin subir archivo)" hace lo mismo sin
   pedir un archivo.
5. Con el documento reunido, click **"Auditar (IA)"** para que se lea el
   contenido real y se cruce contra el requisito exacto de la matriz.

## Qué falta para ser la Fase 3 completa (ver `../plan-implementacion.md`)

- **Parte 2** (extracción real de la matriz desde un PDF de bases subido) —
  acá la matriz/checklist ya viene pre-cargada por el seed; el endpoint
  `/api/ia/analizar-bases` todavía no está construido.
- **Parte 5** (resumen ejecutivo automático + redacción asistida de texto
  libre) — no implementados en este prototipo.
- La auditoría (IA) todavía no lee el contenido real de los archivos subidos
  (`ia.js` deja el gancho listo — `documento.archivo_texto` — pero falta
  extraer texto de PDF/imagen antes de mandarlo a Claude; hoy usa la
  heurística de modo demo aunque haya API key, salvo que se le pase el texto).
- Migración a Postgres + despliegue en Railway (hoy es SQLite local, a
  propósito, para que el prototipo corra sin infraestructura).
- Rate-limiting de los endpoints de IA (sección 14.1 de la arquitectura).

## Estructura

```
src/
  server.js     — Express, todas las rutas /api/*
  db.js         — wrapper sobre node:sqlite
  schema.sql    — las 7 tablas
  seed.js       — carga datos reales + sintéticos
  semaforo.js   — cálculo determinístico del semáforo
  ia.js         — los endpoints de IA, real o modo demo
public/         — frontend (HTML + JS vanilla, mismo criterio sin build step
                  que ya usa ../tablero-netlify)
```
