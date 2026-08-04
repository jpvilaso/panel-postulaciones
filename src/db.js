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

module.exports = { abrirDb, inicializarSchema, all, get, run, DB_PATH };
