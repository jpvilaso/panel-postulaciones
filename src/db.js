const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

// PERSIST_DIR permite apuntar la base a un volumen montado aparte (ej. en
// Railway, donde el resto del contenedor es efímero entre deploys) --
// mismo patrón que ya usa agente-concursos/src/pipeline.js. Sin definirla,
// usa la carpeta local de siempre.
const PERSIST_DIR = process.env.PERSIST_DIR ? path.resolve(process.env.PERSIST_DIR) : path.join(__dirname, '..');
const DB_PATH = path.join(PERSIST_DIR, 'data', 'panel.db');

function abrirDb() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  const db = new DatabaseSync(DB_PATH);
  db.exec('PRAGMA foreign_keys = ON;');
  return db;
}

function inicializarSchema(db) {
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  db.exec(schema);
}

// Migraciones incrementales -- columnas nuevas sobre tablas que ya pueden
// existir con datos reales. `CREATE TABLE IF NOT EXISTS` (inicializarSchema)
// crea tablas que falten por completo, pero no agrega columnas a una tabla
// que ya existe -- eso fue justo el incidente del 2026-08-05 (la tabla
// `matrices_cumplimiento` no existía en producción porque nunca se corrió
// una migración, solo `npm run seed`, que wipea todo y por eso nunca se
// puede correr contra una base con datos reales). Cualquier columna nueva
// sobre una tabla existente tiene que declararse acá -- nunca reescribir el
// CREATE TABLE original con columnas nuevas y asumir que eso alcanza.
const MIGRACIONES_COLUMNAS = [
  { tabla: 'matrices_cumplimiento', columna: 'datos_json_original', definicion: 'TEXT' },
  { tabla: 'matrices_cumplimiento', columna: 'prompt_version', definicion: 'TEXT' },
  { tabla: 'matrices_cumplimiento', columna: 'campos_editados_al_aprobar', definicion: 'INTEGER' },
  { tabla: 'matrices_cumplimiento', columna: 'segundos_hasta_revision', definicion: 'INTEGER' },
  { tabla: 'matrices_cumplimiento', columna: 'requiere_segunda_revision', definicion: 'INTEGER NOT NULL DEFAULT 0' },
  { tabla: 'matrices_cumplimiento', columna: 'motivo_segunda_revision', definicion: 'TEXT' },
  { tabla: 'matrices_cumplimiento', columna: 'primera_revision_por', definicion: 'INTEGER REFERENCES usuarios(id)' },
  { tabla: 'matrices_cumplimiento', columna: 'primera_revision_en', definicion: 'TEXT' },
  { tabla: 'matrices_cumplimiento', columna: 'segunda_revision_por', definicion: 'INTEGER REFERENCES usuarios(id)' },
  { tabla: 'matrices_cumplimiento', columna: 'segunda_revision_en', definicion: 'TEXT' },
  { tabla: 'matrices_cumplimiento', columna: 'segunda_revision_decision', definicion: 'TEXT' },
  { tabla: 'matrices_cumplimiento', columna: 'segunda_revision_detalle', definicion: 'TEXT' },
];

// Se llama al abrir la base en server.js (no solo en seed.js) -- así un
// deploy que agregue una columna nueva se autorepara al arrancar, sin
// necesitar un paso manual de `railway ssh` como el de hoy.
function aplicarMigraciones(db) {
  inicializarSchema(db);
  for (const { tabla, columna, definicion } of MIGRACIONES_COLUMNAS) {
    const existeTabla = db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?`).get(tabla);
    if (!existeTabla) continue;
    const columnasActuales = db.prepare(`PRAGMA table_info(${tabla})`).all().map((c) => c.name);
    if (!columnasActuales.includes(columna)) {
      db.exec(`ALTER TABLE ${tabla} ADD COLUMN ${columna} ${definicion}`);
    }
  }
}

// Helpers delgados sobre node:sqlite (API sync tipo better-sqlite3)
function all(db, sql, params = []) {
  return db.prepare(sql).all(...params);
}
function get(db, sql, params = []) {
  return db.prepare(sql).get(...params);
}
function run(db, sql, params = []) {
  return db.prepare(sql).run(...params);
}

module.exports = { abrirDb, inicializarSchema, aplicarMigraciones, all, get, run, DB_PATH };
