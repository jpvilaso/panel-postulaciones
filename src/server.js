require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const jwt = require('jsonwebtoken');
const { abrirDb, all, get, run } = require('./db');
const { calcularSemaforo, porcentajeAvance } = require('./semaforo');
const ia = require('./ia');
const { borradorADocx } = require('./docgen');
const { validarLargo, passwordComprometida } = require('./passwordPolicy');

const db = abrirDb();
const app = express();
const PORT = process.env.PORT || 3300;

// ---------- seguridad de sesión y de login ----------
// Fuerza bruta: 5 intentos fallidos seguidos -> bloqueo temporal, con
// backoff creciente si se repite (15 min, 30 min, 60 min, ...). No hay una
// columna aparte para "cuántas veces se bloqueó" -- se deriva del propio
// contador de intentos_fallidos, que solo se resetea con un login correcto,
// nunca al expirar un bloqueo.
const MAX_INTENTOS_ANTES_DE_BLOQUEO = 5;
const MINUTOS_BLOQUEO_BASE = 15;
function calcularMinutosBloqueo(intentosFallidos) {
  const ciclos = Math.floor((intentosFallidos - 1) / MAX_INTENTOS_ANTES_DE_BLOQUEO);
  return MINUTOS_BLOQUEO_BASE * 2 ** ciclos;
}

// Timeout de sesión (arquitectura-panel-control.md 3.2): 30 min de
// inactividad (cookie "rolling", se renueva en cada request) + 12h de
// duración absoluta máxima, aunque la persona siga activa sin pausa.
const IDLE_MS = 30 * 60 * 1000;
const DURACION_MAXIMA_SESION_MS = 12 * 60 * 60 * 1000;

if (!process.env.SESSION_SECRET && process.env.NODE_ENV === 'production') {
  console.warn('[seguridad] SESSION_SECRET no está definido en producción -- usando un secreto por defecto inseguro.');
}

// ---------- SSO hacia agente-concursos (Fase E) ----------
// JWT_SECRET tiene que ser EXACTAMENTE el mismo valor configurado en el
// servicio de Railway de agente-concursos -- es lo único que los conecta,
// no comparten base de datos ni sesión. AGENTE_CONCURSOS_URL es el origen
// permitido para "volver" después del SSO (evita que /sso/agente-concursos
// se pueda usar como un open redirect hacia cualquier sitio).
const JWT_SECRET = process.env.JWT_SECRET || null;
const AGENTE_CONCURSOS_URL = process.env.AGENTE_CONCURSOS_URL || null;
if (!JWT_SECRET) {
  console.warn('[seguridad] JWT_SECRET no está definido -- /sso/agente-concursos no va a funcionar hasta configurarlo.');
}

// Mismo PERSIST_DIR que db.js -- si se define (ej. volumen de Railway), los
// archivos subidos quedan junto a la base de datos, en el mismo volumen
// persistente, en vez de perderse en cada redeploy.
const PERSIST_DIR = process.env.PERSIST_DIR ? path.resolve(process.env.PERSIST_DIR) : path.join(__dirname, '..');
const UPLOADS_DIR = path.join(PERSIST_DIR, 'data', 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
      const limpio = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
      cb(null, `doc-${req.params.id}-${Date.now()}-${limpio}`);
    },
  }),
  limits: { fileSize: 20 * 1024 * 1024 },
});

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'demo-panel-postulaciones-secreto-local',
  resave: false,
  saveUninitialized: false,
  rolling: true, // cada request renueva el maxAge -- así maxAge funciona como timeout de INACTIVIDAD, no de vida fija.
  cookie: { maxAge: IDLE_MS },
}));

// ---------- helpers ----------
// Rutas permitidas aunque la cuenta tenga un cambio de contraseña pendiente
// (debe_cambiar_password) -- todo lo demás queda bloqueado hasta que la
// persona cambie la clave, para que el "cambio forzado en el primer ingreso"
// (arquitectura-panel-control.md 3.2) sea real y no solo una sugerencia de UI.
const RUTAS_PERMITIDAS_CON_CAMBIO_PENDIENTE = ['/api/logout', '/api/cambiar-password', '/api/me'];

// Rutas permitidas aunque la cuenta todavía no tenga el 2FA activado -- las
// justas para completar el enrolamiento. Todo el resto del sistema queda
// bloqueado hasta que exista un TOTP confirmado, igual que con el cambio de
// contraseña de arriba.
const RUTAS_PERMITIDAS_SIN_TOTP = ['/api/logout', '/api/me', '/api/2fa/iniciar-enrolamiento', '/api/2fa/confirmar'];

function registrarLogSeguridad(usuarioId, accion, detalle, ip) {
  run(db, 'INSERT INTO log_seguridad (usuario_id, accion, detalle, ip) VALUES (?,?,?,?)',
    [usuarioId, accion, detalle || null, ip || null]);
}

function usuarioActual(req) {
  if (!req.session.usuarioId) return null;
  if (req.session.creadaEn && Date.now() - req.session.creadaEn > DURACION_MAXIMA_SESION_MS) {
    return null; // venció la duración máxima absoluta (12h), aunque haya seguido activa
  }
  const u = get(db, 'SELECT id, nombre, email, rol, activo, debe_cambiar_password, totp_habilitado FROM usuarios WHERE id = ?', [req.session.usuarioId]);
  if (!u || !u.activo) return null; // cuenta desactivada -- ver "desactivar, no borrar" en 3.2
  return u;
}

function requireLogin(req, res, next) {
  const u = usuarioActual(req);
  if (!u) return res.status(401).json({ error: 'No autenticado' });
  if (u.debe_cambiar_password && !RUTAS_PERMITIDAS_CON_CAMBIO_PENDIENTE.includes(req.path)) {
    return res.status(403).json({ error: 'Debes cambiar tu contraseña antes de continuar.', debeCambiarPassword: true });
  }
  if (!u.totp_habilitado && !RUTAS_PERMITIDAS_SIN_TOTP.includes(req.path)) {
    return res.status(403).json({ error: 'Debes activar la verificación en dos pasos antes de continuar.', requiereConfigurarTotp: true });
  }
  req.usuario = u;
  next();
}

// El "?volver=" encadena la URL originalmente pedida a través de cada
// paso de onboarding pendiente (login -> cambiar clave -> activar 2FA), para
// que /sso/agente-concursos pueda recuperar el control apenas la sesión
// quede completa, en vez de perder de vista a dónde había que volver.
function conVolver(destino, req) {
  return `${destino}?volver=${encodeURIComponent(req.originalUrl)}`;
}

function requireLoginRedirect(req, res, next) {
  const u = usuarioActual(req);
  if (!u) return res.redirect(conVolver('/login.html', req));
  if (u.debe_cambiar_password) return res.redirect(conVolver('/cambiar-password.html', req));
  if (!u.totp_habilitado) return res.redirect(conVolver('/configurar-2fa.html', req));
  next();
}

function generarCodigoRespaldo() {
  const raw = crypto.randomBytes(5).toString('hex').toUpperCase(); // 10 caracteres hex
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

function requireRol(...roles) {
  return (req, res, next) => {
    // admin trae todos los permisos por defecto (3.2) -- pasa cualquier
    // guardia de rol sin tener que listarlo en cada llamada a requireRol.
    if (req.usuario.rol === 'admin') return next();
    if (!roles.includes(req.usuario.rol)) return res.status(403).json({ error: 'Rol sin permiso' });
    next();
  };
}

// Permisos por defecto según rol (arquitectura-panel-control.md 3.2) --
// `usuario_permisos` guarda solo EXCEPCIONES sobre esto; sin fila para un
// permiso puntual, manda el default del rol. admin y director traen
// `gestionar_usuarios` de fábrica; equipo no, salvo que alguien le dé la
// excepción puntual desde el panel de Configuración.
const PERMISOS_DEFAULT_POR_ROL = {
  admin: ['gestionar_usuarios'],
  director: ['gestionar_usuarios'],
  equipo: [],
};
function tienePermiso(usuario, permiso) {
  const excepcion = get(db, 'SELECT otorgado FROM usuario_permisos WHERE usuario_id = ? AND permiso = ?', [usuario.id, permiso]);
  if (excepcion) return !!excepcion.otorgado;
  return (PERMISOS_DEFAULT_POR_ROL[usuario.rol] || []).includes(permiso);
}
function requirePermiso(permiso) {
  return (req, res, next) => {
    if (!tienePermiso(req.usuario, permiso)) return res.status(403).json({ error: 'No tienes permiso para esto.' });
    next();
  };
}

function postulacionConSemaforo(p) {
  const documentos = all(db, 'SELECT * FROM documentos WHERE postulacion_id = ?', [p.id]);
  const semaforo = calcularSemaforo(p, documentos);
  const avance = porcentajeAvance(documentos);
  return { ...p, semaforo: semaforo.color, semaforo_razon: semaforo.razon, avance, n_documentos: documentos.length };
}

function registrarLog(postulacionId, usuarioId, accion, detalle) {
  run(db, 'INSERT INTO log_eventos (postulacion_id, usuario_id, accion, detalle) VALUES (?,?,?,?)',
    [postulacionId, usuarioId, accion, detalle]);
}

// Documentos de TODAS las postulaciones (no solo "activas"), para el
// checklist agregado del panel del equipo y del panel del director —
// a propósito no filtra por resultado: una postulación ya "adjudicada"
// (ej. FFOP 2026) puede seguir teniendo documentos pendientes (fase
// "convenio") que igual hay que ver en el checklist global.
function documentosDeTodas() {
  return all(db, `
    SELECT d.*, p.id AS postulacion_id, c.titulo AS convocatoria_titulo,
           c.fuente AS convocatoria_fuente, p.folio, p.resultado,
           ur.nombre AS responsable_nombre
    FROM documentos d
    JOIN postulaciones p ON p.id = d.postulacion_id
    JOIN convocatorias c ON c.id = p.convocatoria_id
    LEFT JOIN usuarios ur ON ur.id = d.responsable_id
    ORDER BY p.id, d.id`);
}

// Recalcula postulaciones.proximo_hito/proximo_hito_fecha a partir de la
// tabla `hitos` — el hito pendiente (cumplido=0) con la fecha más próxima,
// sea futura o ya vencida (si ya venció y sigue sin cumplirse, el semáforo
// necesita saberlo tal como antes, cuando el campo se escribía a mano).
// Si no queda ningún hito pendiente, deja ambos campos en null.
function recalcularProximoHito(postulacionId) {
  const proximo = get(db, `
    SELECT titulo, fecha FROM hitos WHERE postulacion_id = ? AND cumplido = 0
    ORDER BY fecha ASC LIMIT 1`, [postulacionId]);
  run(db, 'UPDATE postulaciones SET proximo_hito = ?, proximo_hito_fecha = ? WHERE id = ?',
    [proximo ? proximo.titulo : null, proximo ? proximo.fecha : null, postulacionId]);
}

// Notifica a alguien salvo que sea la misma persona que gatilló la acción
// (nadie necesita una notificación de su propia acción).
function notificarSiCorresponde(usuarioDestinoId, actorId, postulacionId, tipo, mensaje) {
  if (!usuarioDestinoId || usuarioDestinoId === actorId) return;
  run(db, 'INSERT INTO notificaciones (usuario_id, postulacion_id, tipo, mensaje, leida) VALUES (?,?,?,?,0)',
    [usuarioDestinoId, postulacionId, tipo, mensaje]);
}

// Flujo de aprobación con recordatorio automático (inspirado en las
// automatizaciones de Monday.com: "si pasan 48h sin aprobar, recuerda") —
// un anexo generado por IA que sigue sin aprobarse/reunirse pasado el
// plazo dispara una notificación al responsable, una sola vez por borrador
// (ver comentario de `recordatorio_enviado_en` en schema.sql).
//
// Este prototipo no tiene un proceso en segundo plano (cron) corriendo
// aparte del servidor web — se revisa "de paso" cada vez que se abre un
// panel (equipo o director), que es cuando de verdad importa que alguien
// se entere. Si esto se despliega con tráfico bajo (nadie abre el panel
// por días), un cron real sería más confiable; queda anotado como límite
// conocido, no un bug.
const HORAS_RECORDATORIO_ANEXO = 48;
function revisarRecordatoriosPendientes() {
  const limite = new Date(Date.now() - HORAS_RECORDATORIO_ANEXO * 60 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' ');
  const pendientes = all(db, `
    SELECT d.*, p.responsable_id AS postulacion_responsable_id, c.titulo AS convocatoria_titulo
    FROM documentos d
    JOIN postulaciones p ON p.id = d.postulacion_id
    JOIN convocatorias c ON c.id = p.convocatoria_id
    WHERE d.origen = 'generado_ia' AND d.contenido_generado IS NOT NULL AND d.estado != 'reunido'
      AND d.generado_en IS NOT NULL AND d.generado_en <= ?
      AND d.recordatorio_enviado_en IS NULL`, [limite]);
  for (const d of pendientes) {
    const destino = d.responsable_id || d.postulacion_responsable_id;
    if (destino) {
      run(db, 'INSERT INTO notificaciones (usuario_id, postulacion_id, tipo, mensaje, leida) VALUES (?,?,?,?,0)',
        [destino, d.postulacion_id, 'recordatorio_aprobacion',
          `"${d.tipo}" (${d.convocatoria_titulo}) lleva más de ${HORAS_RECORDATORIO_ANEXO}h esperando revisión.`]);
    }
    run(db, `UPDATE documentos SET recordatorio_enviado_en = datetime('now') WHERE id = ?`, [d.id]);
    registrarLog(d.postulacion_id, null, 'recordatorio_aprobacion_enviado', `"${d.tipo}" — sin revisar ${HORAS_RECORDATORIO_ANEXO}h+, recordatorio enviado.`);
  }
  return pendientes.length;
}

// ---------- auth ----------
function destinoParaRol(rol) {
  return (rol === 'director' || rol === 'admin') ? '/panel-director.html' : '/panel-equipo.html';
}

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  const { email, password } = req.body || {};
  const emailNormalizado = (email || '').toLowerCase().trim();
  const u = get(db, 'SELECT * FROM usuarios WHERE email = ?', [emailNormalizado]);

  if (!u) {
    registrarLogSeguridad(null, 'login_fallido', `Email no registrado: ${emailNormalizado}`, ip);
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
  }

  if (!u.activo) {
    registrarLogSeguridad(u.id, 'login_fallido', 'Cuenta desactivada.', ip);
    return res.status(403).json({ error: 'Esta cuenta está desactivada. Contacta a un administrador.' });
  }

  if (u.bloqueado_hasta && new Date(`${u.bloqueado_hasta}Z`) > new Date()) {
    const minutosRestantes = Math.ceil((new Date(`${u.bloqueado_hasta}Z`) - new Date()) / 60000);
    registrarLogSeguridad(u.id, 'login_fallido', `Cuenta bloqueada, quedan ${minutosRestantes} min.`, ip);
    return res.status(423).json({ error: `Demasiados intentos fallidos. Intenta de nuevo en ${minutosRestantes} minuto(s).` });
  }

  if (!bcrypt.compareSync(password || '', u.password_hash)) {
    const intentos = u.intentos_fallidos + 1;
    let bloqueadoHasta = null;
    if (intentos % MAX_INTENTOS_ANTES_DE_BLOQUEO === 0) {
      const minutos = calcularMinutosBloqueo(intentos);
      bloqueadoHasta = new Date(Date.now() + minutos * 60000).toISOString().slice(0, 19).replace('T', ' ');
      registrarLogSeguridad(u.id, 'bloqueo', `Bloqueada ${minutos} min tras ${intentos} intentos fallidos.`, ip);
    }
    run(db, 'UPDATE usuarios SET intentos_fallidos = ?, bloqueado_hasta = ? WHERE id = ?', [intentos, bloqueadoHasta, u.id]);
    registrarLogSeguridad(u.id, 'login_fallido', `Intento ${intentos}.`, ip);
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
  }

  // Credenciales correctas.
  run(db, 'UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?', [u.id]);

  // Con 2FA ya activado, la contraseña sola no basta -- se deja la cuenta
  // "pendiente de TOTP" y recién se abre la sesión real en /api/login/totp.
  // Sin 2FA todavía (cuenta nueva o legado), sí se entra directo, pero
  // requireLogin la deja encerrada en el flujo de enrolamiento hasta que lo
  // complete (mismo patrón que debe_cambiar_password).
  if (u.totp_habilitado) {
    req.session.totpPendienteId = u.id;
    registrarLogSeguridad(u.id, 'login_ok', 'Credenciales correctas, pendiente de código TOTP.', ip);
    return res.json({ requiereTotp: true });
  }

  req.session.usuarioId = u.id;
  req.session.creadaEn = Date.now();
  registrarLogSeguridad(u.id, 'login_ok', 'Sin 2FA activado todavía.', ip);

  if (u.debe_cambiar_password) {
    return res.json({ nombre: u.nombre, rol: u.rol, debeCambiarPassword: true, destino: '/cambiar-password.html' });
  }
  res.json({ nombre: u.nombre, rol: u.rol, debeCambiarPassword: false, destino: '/configurar-2fa.html' });
});

// Segundo factor del login -- solo válido tras un /api/login exitoso que
// dejó la sesión en estado "pendiente de TOTP" (nunca se llega acá sin
// haber pasado antes por la contraseña correcta). Acepta un código TOTP de
// 6 dígitos o, si la persona perdió el dispositivo, uno de los códigos de
// respaldo de un solo uso -- ambos cuentan para el mismo contador de
// fuerza bruta que la contraseña (mismo umbral, mismo bloqueo).
app.post('/api/login/totp', (req, res) => {
  const ip = req.ip;
  const pendienteId = req.session.totpPendienteId;
  if (!pendienteId) return res.status(400).json({ error: 'No hay un inicio de sesión pendiente de verificación en dos pasos.' });

  const u = get(db, 'SELECT * FROM usuarios WHERE id = ?', [pendienteId]);
  if (!u || !u.activo) {
    req.session.totpPendienteId = null;
    return res.status(401).json({ error: 'No autenticado' });
  }

  if (u.bloqueado_hasta && new Date(`${u.bloqueado_hasta}Z`) > new Date()) {
    const minutosRestantes = Math.ceil((new Date(`${u.bloqueado_hasta}Z`) - new Date()) / 60000);
    return res.status(423).json({ error: `Demasiados intentos fallidos. Intenta de nuevo en ${minutosRestantes} minuto(s).` });
  }

  const { codigo, codigoRespaldo } = req.body || {};
  let valido = false;
  let usoCodigoRespaldo = false;

  if (codigo) {
    valido = authenticator.check(String(codigo).trim(), u.totp_secret);
  } else if (codigoRespaldo) {
    const candidatos = all(db, 'SELECT * FROM totp_codigos_respaldo WHERE usuario_id = ? AND usado = 0', [u.id]);
    const match = candidatos.find((c) => bcrypt.compareSync(String(codigoRespaldo).trim().toUpperCase(), c.codigo_hash));
    if (match) {
      run(db, 'UPDATE totp_codigos_respaldo SET usado = 1 WHERE id = ?', [match.id]);
      registrarLogSeguridad(u.id, 'codigo_respaldo_usado', null, ip);
      valido = true;
      usoCodigoRespaldo = true;
    }
  }

  if (!valido) {
    const intentos = u.intentos_fallidos + 1;
    let bloqueadoHasta = null;
    if (intentos % MAX_INTENTOS_ANTES_DE_BLOQUEO === 0) {
      const minutos = calcularMinutosBloqueo(intentos);
      bloqueadoHasta = new Date(Date.now() + minutos * 60000).toISOString().slice(0, 19).replace('T', ' ');
      registrarLogSeguridad(u.id, 'bloqueo', `Bloqueada ${minutos} min tras ${intentos} intentos fallidos (incluye TOTP).`, ip);
    }
    run(db, 'UPDATE usuarios SET intentos_fallidos = ?, bloqueado_hasta = ? WHERE id = ?', [intentos, bloqueadoHasta, u.id]);
    registrarLogSeguridad(u.id, 'login_fallido', `Código de verificación en dos pasos incorrecto (intento ${intentos}).`, ip);
    return res.status(401).json({ error: 'Código incorrecto.' });
  }

  run(db, 'UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?', [u.id]);
  req.session.totpPendienteId = null;
  req.session.usuarioId = u.id;
  req.session.creadaEn = Date.now();
  registrarLogSeguridad(u.id, 'login_ok', usoCodigoRespaldo ? 'Vía código de respaldo.' : 'Vía TOTP.', ip);

  const respuesta = { nombre: u.nombre, rol: u.rol, destino: u.debe_cambiar_password ? '/cambiar-password.html' : destinoParaRol(u.rol) };
  if (usoCodigoRespaldo) {
    const restantes = get(db, 'SELECT COUNT(*) AS n FROM totp_codigos_respaldo WHERE usuario_id = ? AND usado = 0', [u.id]).n;
    if (restantes <= 2) {
      respuesta.avisoCodigosRespaldo = `Te quedan ${restantes} código(s) de respaldo sin usar. Genera nuevos desde tu perfil pronto.`;
    }
  }
  res.json(respuesta);
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// SSO hacia agente-concursos -- reemplaza el Basic Auth compartido de ese
// sitio (Fase E). Guardado por requireLoginRedirect: si la sesión no está
// completa (sin login, cambio de clave pendiente o 2FA sin activar), rebota
// por el flujo normal de onboarding y vuelve a caer acá solo. Una vez que
// hay sesión completa, firma un JWT de corta vida (12h, igual que el tope
// de sesión) y redirige de vuelta a "volver" con el token en el FRAGMENTO
// de la URL (#token=...) -- un fragmento nunca sale del navegador (no queda
// en logs de servidor ni en el historial de Netlify), a diferencia de un
// query param.
app.get('/sso/agente-concursos', requireLoginRedirect, (req, res) => {
  if (!JWT_SECRET) return res.status(500).send('JWT_SECRET no está configurado en este servidor.');
  const volver = req.query.volver;
  if (!volver) return res.status(400).send('Falta el parámetro "volver".');
  if (AGENTE_CONCURSOS_URL) {
    try {
      if (new URL(volver).origin !== new URL(AGENTE_CONCURSOS_URL).origin) {
        return res.status(400).send('Destino de retorno no permitido.');
      }
    } catch {
      return res.status(400).send('URL de retorno inválida.');
    }
  }
  const usuario = usuarioActual(req);
  const token = jwt.sign({
    sub: usuario.id, nombre: usuario.nombre, email: usuario.email, rol: usuario.rol,
    gestionar_usuarios: tienePermiso(usuario, 'gestionar_usuarios'),
  }, JWT_SECRET, { expiresIn: '12h', issuer: 'panel-postulaciones', audience: 'agente-concursos' });
  registrarLogSeguridad(usuario.id, 'login_ok', 'SSO hacia agente-concursos.', req.ip);
  const separador = volver.includes('#') ? '&' : '#';
  res.redirect(`${volver}${separador}token=${encodeURIComponent(token)}`);
});

// Incluye el permiso "gestionar_usuarios" ya resuelto (rol + excepción) --
// lo usa initNav() en común.js para decidir si muestra el link de
// Configuración, que ya no depende solo de rol === 'director'/'admin'.
app.get('/api/me', requireLogin, (req, res) => {
  res.json({ ...req.usuario, gestionar_usuarios: tienePermiso(req.usuario, 'gestionar_usuarios') });
});

// ---------- 2FA (TOTP) ----------
// Genera un secreto nuevo y lo deja guardado sin confirmar todavía
// (totp_habilitado sigue en 0 hasta /api/2fa/confirmar) -- llamar de nuevo
// antes de confirmar simplemente reemplaza el secreto pendiente, no hay
// problema en reintentar si el QR no escaneó bien la primera vez.
app.post('/api/2fa/iniciar-enrolamiento', requireLogin, async (req, res) => {
  const secret = authenticator.generateSecret();
  run(db, 'UPDATE usuarios SET totp_secret = ? WHERE id = ?', [secret, req.usuario.id]);
  const otpauth = authenticator.keyuri(req.usuario.email, 'Agente de Concursos Públicos', secret);
  const qr = await qrcode.toDataURL(otpauth);
  res.json({ qr, secretManual: secret });
});

// Confirma el enrolamiento con un código real del authenticator y genera
// los códigos de respaldo -- se devuelven en texto plano UNA sola vez acá;
// de ahí en adelante solo se guarda su hash (totp_codigos_respaldo), igual
// que una contraseña.
app.post('/api/2fa/confirmar', requireLogin, (req, res) => {
  const { codigo } = req.body || {};
  const u = get(db, 'SELECT * FROM usuarios WHERE id = ?', [req.usuario.id]);
  if (!u.totp_secret) return res.status(400).json({ error: 'Primero inicia el enrolamiento.' });
  if (!authenticator.check(String(codigo || '').trim(), u.totp_secret)) {
    registrarLogSeguridad(u.id, 'login_fallido', 'Código TOTP incorrecto durante el enrolamiento.', req.ip);
    return res.status(400).json({ error: 'Código incorrecto. Revisa la hora de tu teléfono e intenta de nuevo.' });
  }

  const codigosRespaldo = Array.from({ length: 10 }, generarCodigoRespaldo);
  for (const codigo2 of codigosRespaldo) {
    run(db, 'INSERT INTO totp_codigos_respaldo (usuario_id, codigo_hash) VALUES (?,?)', [u.id, bcrypt.hashSync(codigo2, 10)]);
  }
  run(db, 'UPDATE usuarios SET totp_habilitado = 1 WHERE id = ?', [u.id]);
  registrarLogSeguridad(u.id, 'totp_habilitado', null, req.ip);

  res.json({
    ok: true,
    codigosRespaldo,
    destino: u.debe_cambiar_password ? '/cambiar-password.html' : destinoParaRol(u.rol),
  });
});

// Cambio de contraseña -- usado tanto para el cambio forzado del primer
// ingreso (debe_cambiar_password) como para un cambio voluntario cualquiera.
// Siempre pide la contraseña actual, incluso en el cambio forzado (la
// persona ya la conoce: es la temporal que le dieron al crear la cuenta).
app.post('/api/cambiar-password', requireLogin, async (req, res) => {
  const { passwordActual, passwordNueva } = req.body || {};
  const u = get(db, 'SELECT * FROM usuarios WHERE id = ?', [req.usuario.id]);
  if (!bcrypt.compareSync(passwordActual || '', u.password_hash)) {
    registrarLogSeguridad(u.id, 'login_fallido', 'Contraseña actual incorrecta al intentar cambiarla.', req.ip);
    return res.status(401).json({ error: 'La contraseña actual no es correcta.' });
  }
  const chequeoLargo = validarLargo(passwordNueva);
  if (!chequeoLargo.valido) return res.status(400).json({ error: chequeoLargo.motivo });

  if (await passwordComprometida(passwordNueva)) {
    return res.status(400).json({ error: 'Esa contraseña aparece en filtraciones conocidas. Elige otra.' });
  }

  const nuevoHash = bcrypt.hashSync(passwordNueva, 10);
  run(db, `UPDATE usuarios SET password_hash = ?, debe_cambiar_password = 0,
           password_actualizada_en = datetime('now') WHERE id = ?`, [nuevoHash, u.id]);
  registrarLogSeguridad(u.id, 'cambio_password', null, req.ip);
  res.json({ ok: true, destino: destinoParaRol(u.rol) });
});

// ---------- buscador global (postulaciones, folios y documentos) ----------
app.get('/api/buscar', requireLogin, (req, res) => {
  const q = (req.query.q || '').trim();
  if (q.length < 2) return res.json({ postulaciones: [], documentos: [] });
  const like = `%${q}%`;
  const postulaciones = all(db, `
    SELECT p.id, c.titulo AS convocatoria_titulo, c.fuente AS convocatoria_fuente, p.folio, p.resultado
    FROM postulaciones p
    JOIN convocatorias c ON c.id = p.convocatoria_id
    WHERE c.titulo LIKE ? OR p.folio LIKE ?
    ORDER BY p.id LIMIT 20`, [like, like]);
  const documentos = all(db, `
    SELECT d.id, d.tipo, d.estado, d.estado_auditoria, d.postulacion_id, c.titulo AS convocatoria_titulo
    FROM documentos d
    JOIN postulaciones p ON p.id = d.postulacion_id
    JOIN convocatorias c ON c.id = p.convocatoria_id
    WHERE d.tipo LIKE ?
    ORDER BY d.id LIMIT 30`, [like]);
  res.json({ postulaciones, documentos });
});

// ---------- monitoreo (Etapa 1, solo lectura, cualquier rol) ----------
app.get('/api/monitoreo', requireLogin, (req, res) => {
  const rows = all(db, 'SELECT * FROM convocatorias ORDER BY (fecha_cierre IS NULL), fecha_cierre ASC');
  res.json(rows);
});

// ---------- postulaciones ----------
app.get('/api/postulaciones', requireLogin, (req, res) => {
  const rows = all(db, `
    SELECT p.*, c.titulo AS convocatoria_titulo, c.fuente AS convocatoria_fuente,
           u.nombre AS responsable_nombre
    FROM postulaciones p
    JOIN convocatorias c ON c.id = p.convocatoria_id
    LEFT JOIN usuarios u ON u.id = p.responsable_id
    ORDER BY p.id`);
  // Todos los hitos de todas las postulaciones en una sola consulta (en vez
  // de una por postulación) y se agrupan acá — usado por calendario.html
  // para mostrar el cronograma completo, no solo "el próximo".
  const todosHitos = all(db, 'SELECT * FROM hitos ORDER BY fecha ASC');
  const hitosPorPostulacion = {};
  for (const h of todosHitos) {
    (hitosPorPostulacion[h.postulacion_id] ||= []).push(h);
  }
  res.json(rows.map(postulacionConSemaforo).map((p) => ({ ...p, hitos: hitosPorPostulacion[p.id] || [] })));
});

app.get('/api/postulaciones/:id', requireLogin, (req, res) => {
  const p = get(db, `
    SELECT p.*, c.titulo AS convocatoria_titulo, c.fuente AS convocatoria_fuente,
           c.descripcion AS convocatoria_descripcion, c.link AS convocatoria_link,
           u.nombre AS responsable_nombre
    FROM postulaciones p
    JOIN convocatorias c ON c.id = p.convocatoria_id
    LEFT JOIN usuarios u ON u.id = p.responsable_id
    WHERE p.id = ?`, [req.params.id]);
  if (!p) return res.status(404).json({ error: 'No existe' });
  const documentos = all(db, `
    SELECT d.*, ur.nombre AS responsable_nombre
    FROM documentos d
    LEFT JOIN usuarios ur ON ur.id = d.responsable_id
    WHERE d.postulacion_id = ? ORDER BY d.id`, [p.id]);
  const eventos = all(db, `
    SELECT le.*, u.nombre AS usuario_nombre FROM log_eventos le
    LEFT JOIN usuarios u ON u.id = le.usuario_id
    WHERE le.postulacion_id = ? ORDER BY le.id DESC`, [p.id]);
  const comentarios = all(db, `
    SELECT co.*, u.nombre AS usuario_nombre, d.tipo AS documento_tipo FROM comentarios co
    JOIN usuarios u ON u.id = co.usuario_id
    LEFT JOIN documentos d ON d.id = co.documento_id
    WHERE co.postulacion_id = ? ORDER BY co.id ASC`, [p.id]);
  const hitos = all(db, 'SELECT * FROM hitos WHERE postulacion_id = ? ORDER BY fecha ASC', [p.id]);
  const camposPersonalizados = all(db, 'SELECT * FROM campos_personalizados WHERE postulacion_id = ? ORDER BY id', [p.id]);
  const semaforo = calcularSemaforo(p, documentos);
  res.json({ ...p, semaforo: semaforo.color, semaforo_razon: semaforo.razon, avance: porcentajeAvance(documentos), documentos, eventos, comentarios, hitos, camposPersonalizados });
});

// ---------- campos personalizados (clave→valor libre por postulación) ----------
app.post('/api/postulaciones/:id/campos', requireLogin, requireRol('equipo', 'director'), (req, res) => {
  const postulacion = get(db, 'SELECT * FROM postulaciones WHERE id = ?', [req.params.id]);
  if (!postulacion) return res.status(404).json({ error: 'No existe' });
  const clave = (req.body.clave || '').trim();
  const valor = (req.body.valor || '').trim();
  if (!clave) return res.status(400).json({ error: 'El campo necesita un nombre.' });
  if (!valor) return res.status(400).json({ error: 'El campo necesita un valor.' });
  run(db, `
    INSERT INTO campos_personalizados (postulacion_id, clave, valor) VALUES (?,?,?)
    ON CONFLICT(postulacion_id, clave) DO UPDATE SET valor = excluded.valor`,
    [postulacion.id, clave, valor]);
  registrarLog(postulacion.id, req.usuario.id, 'campo_personalizado_actualizado', `"${clave}" = "${valor}".`);
  res.json({ ok: true });
});

app.delete('/api/campos/:id', requireLogin, requireRol('equipo', 'director'), (req, res) => {
  const campo = get(db, 'SELECT * FROM campos_personalizados WHERE id = ?', [req.params.id]);
  if (!campo) return res.status(404).json({ error: 'No existe' });
  run(db, 'DELETE FROM campos_personalizados WHERE id = ?', [campo.id]);
  registrarLog(campo.postulacion_id, req.usuario.id, 'campo_personalizado_eliminado', `"${campo.clave}" eliminado.`);
  res.json({ ok: true });
});

// ---------- hitos (varios por postulación, ver `recalcularProximoHito`) ----------
app.post('/api/postulaciones/:id/hitos', requireLogin, requireRol('equipo', 'director'), (req, res) => {
  const postulacion = get(db, 'SELECT * FROM postulaciones WHERE id = ?', [req.params.id]);
  if (!postulacion) return res.status(404).json({ error: 'No existe' });
  const titulo = (req.body.titulo || '').trim();
  const fecha = (req.body.fecha || '').trim();
  if (!titulo) return res.status(400).json({ error: 'El hito necesita un título.' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha)) return res.status(400).json({ error: 'Fecha inválida (formato AAAA-MM-DD).' });
  const r = run(db, 'INSERT INTO hitos (postulacion_id, titulo, fecha) VALUES (?,?,?)', [postulacion.id, titulo, fecha]);
  recalcularProximoHito(postulacion.id);
  registrarLog(postulacion.id, req.usuario.id, 'hito_agregado', `"${titulo}" — ${fecha}.`);
  res.json({ ok: true, id: r.lastInsertRowid });
});

app.post('/api/hitos/:id/cumplido', requireLogin, requireRol('equipo', 'director'), (req, res) => {
  const hito = get(db, 'SELECT * FROM hitos WHERE id = ?', [req.params.id]);
  if (!hito) return res.status(404).json({ error: 'No existe' });
  const cumplido = req.body.cumplido ? 1 : 0;
  run(db, 'UPDATE hitos SET cumplido = ? WHERE id = ?', [cumplido, hito.id]);
  recalcularProximoHito(hito.postulacion_id);
  registrarLog(hito.postulacion_id, req.usuario.id, 'hito_actualizado', `"${hito.titulo}" marcado como ${cumplido ? 'cumplido' : 'pendiente'}.`);
  res.json({ ok: true });
});

app.delete('/api/hitos/:id', requireLogin, requireRol('equipo', 'director'), (req, res) => {
  const hito = get(db, 'SELECT * FROM hitos WHERE id = ?', [req.params.id]);
  if (!hito) return res.status(404).json({ error: 'No existe' });
  run(db, 'DELETE FROM hitos WHERE id = ?', [hito.id]);
  recalcularProximoHito(hito.postulacion_id);
  registrarLog(hito.postulacion_id, req.usuario.id, 'hito_eliminado', `"${hito.titulo}" (${hito.fecha}) eliminado.`);
  res.json({ ok: true });
});

// Usuarios del equipo, para poblar selectores de "asignar responsable" —
// cualquier rol logueado puede verlos (director también puede asignar).
app.get('/api/usuarios-equipo', requireLogin, (req, res) => {
  res.json(all(db, `SELECT id, nombre FROM usuarios WHERE rol = 'equipo' ORDER BY nombre`));
});

// ---------- invitados externos (acceso acotado, sin cuenta) ----------
// Gestión interna (equipo/director) de las invitaciones de una postulación.
app.get('/api/postulaciones/:id/invitados', requireLogin, requireRol('equipo', 'director'), (req, res) => {
  const filas = all(db, `
    SELECT i.*, u.nombre AS creado_por_nombre FROM invitados i
    LEFT JOIN usuarios u ON u.id = i.creado_por
    WHERE i.postulacion_id = ? ORDER BY i.id DESC`, [req.params.id]);
  res.json(filas);
});

app.post('/api/postulaciones/:id/invitados', requireLogin, requireRol('equipo', 'director'), (req, res) => {
  const postulacion = get(db, 'SELECT * FROM postulaciones WHERE id = ?', [req.params.id]);
  if (!postulacion) return res.status(404).json({ error: 'No existe' });
  const nombre = (req.body.nombre || '').trim();
  if (!nombre) return res.status(400).json({ error: 'El invitado necesita un nombre (para dejar registro de quién es).' });
  const expiraEn = (req.body.expira_en || '').trim() || null;
  if (expiraEn && !/^\d{4}-\d{2}-\d{2}$/.test(expiraEn)) return res.status(400).json({ error: 'Fecha de expiración inválida (formato AAAA-MM-DD).' });
  const token = crypto.randomBytes(20).toString('hex');
  run(db, `INSERT INTO invitados (postulacion_id, token, nombre, puede_subir_archivo, creado_por, expira_en)
           VALUES (?,?,?,?,?,?)`,
    [postulacion.id, token, nombre, req.body.puede_subir_archivo ? 1 : 0, req.usuario.id, expiraEn]);
  registrarLog(postulacion.id, req.usuario.id, 'invitado_creado', `Acceso externo creado para "${nombre}".`);
  res.json({ ok: true, token });
});

app.post('/api/invitados/:id/revocar', requireLogin, requireRol('equipo', 'director'), (req, res) => {
  const invitado = get(db, 'SELECT * FROM invitados WHERE id = ?', [req.params.id]);
  if (!invitado) return res.status(404).json({ error: 'No existe' });
  run(db, 'UPDATE invitados SET revocado = 1 WHERE id = ?', [invitado.id]);
  registrarLog(invitado.postulacion_id, req.usuario.id, 'invitado_revocado', `Acceso externo de "${invitado.nombre}" revocado.`);
  res.json({ ok: true });
});

// Valida un token de invitado — null si no existe, está revocado o venció.
// Nunca distingue el motivo en la respuesta pública (mismo error genérico
// para "no existe" y "revocado/vencido"), para no filtrarle a quien prueba
// tokens al azar si casi acertó.
function invitadoValido(token) {
  const invitado = get(db, 'SELECT * FROM invitados WHERE token = ?', [token]);
  if (!invitado || invitado.revocado) return null;
  if (invitado.expira_en && invitado.expira_en < new Date().toISOString().slice(0, 10)) return null;
  return invitado;
}

// Vista pública (sin login) — acotada a los documentos que requieren firma
// externa de esa postulación, nunca al checklist completo ni a documentos
// `sensible`. Es el único punto de entrada que ve alguien sin cuenta.
app.get('/api/invitado/:token', (req, res) => {
  const invitado = invitadoValido(req.params.token);
  if (!invitado) return res.status(404).json({ error: 'Este enlace ya no es válido (revocado, vencido o no existe).' });
  const postulacion = get(db, `
    SELECT p.id, p.folio, p.resultado, c.titulo AS convocatoria_titulo, c.fuente AS convocatoria_fuente
    FROM postulaciones p JOIN convocatorias c ON c.id = p.convocatoria_id WHERE p.id = ?`, [invitado.postulacion_id]);
  const documentos = all(db, `
    SELECT id, tipo, requisito, estado, estado_firma, archivo_url, contenido_generado
    FROM documentos WHERE postulacion_id = ? AND requiere_firma_externa = 1 AND sensible = 0
    ORDER BY id`, [invitado.postulacion_id]);
  res.json({
    invitado: { nombre: invitado.nombre, puede_subir_archivo: !!invitado.puede_subir_archivo },
    postulacion,
    // archivo_url nunca viaja tal cual (el invitado no tiene sesión y
    // /uploads exige login) — solo si ya está firmada, para mostrar
    // "ya se subió" sin exponer el link directo del archivo interno.
    documentos: documentos.map((d) => ({ ...d, archivo_url: undefined, ya_firmada: !!d.archivo_url })),
  });
});

app.get('/api/invitado/:token/documentos/:id/descargar-borrador', async (req, res) => {
  const invitado = invitadoValido(req.params.token);
  if (!invitado) return res.status(404).json({ error: 'Este enlace ya no es válido.' });
  const doc = get(db, 'SELECT * FROM documentos WHERE id = ? AND postulacion_id = ? AND requiere_firma_externa = 1',
    [req.params.id, invitado.postulacion_id]);
  if (!doc || !doc.contenido_generado) return res.status(404).json({ error: 'No hay borrador disponible para este documento.' });
  const postulacion = get(db, 'SELECT * FROM postulaciones WHERE id = ?', [doc.postulacion_id]);
  const convocatoria = get(db, 'SELECT * FROM convocatorias WHERE id = ?', [postulacion.convocatoria_id]);
  const buffer = await borradorADocx({
    titulo: doc.tipo,
    subtitulo: `${convocatoria.titulo} · ${convocatoria.fuente}`,
    cuerpo: doc.contenido_generado,
  });
  const nombre = doc.tipo.replace(/[^a-zA-Z0-9]+/g, '-').toLowerCase().slice(0, 60);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
  res.setHeader('Content-Disposition', `attachment; filename="${nombre}.docx"`);
  res.send(buffer);
});

app.post('/api/invitado/:token/documentos/:id/subir-archivo', upload.single('archivo'), (req, res) => {
  const invitado = invitadoValido(req.params.token);
  if (!invitado) return res.status(404).json({ error: 'Este enlace ya no es válido.' });
  if (!invitado.puede_subir_archivo) return res.status(403).json({ error: 'Este enlace es de solo lectura, no permite subir archivos.' });
  const doc = get(db, 'SELECT * FROM documentos WHERE id = ? AND postulacion_id = ? AND requiere_firma_externa = 1',
    [req.params.id, invitado.postulacion_id]);
  if (!doc) return res.status(404).json({ error: 'No existe' });
  if (!req.file) return res.status(400).json({ error: 'No se recibió ningún archivo.' });

  const urlPublica = `/uploads/${req.file.filename}`;
  run(db, 'INSERT INTO documento_versiones (documento_id, archivo_url, nombre_original, subido_por_invitado) VALUES (?,?,?,?)',
    [doc.id, urlPublica, req.file.originalname, invitado.nombre]);
  run(db, `UPDATE documentos SET archivo_url = ?, estado_firma = 'firmada', estado = 'reunido' WHERE id = ?`, [urlPublica, doc.id]);
  registrarLog(doc.postulacion_id, null, 'archivo_subido_invitado', `"${doc.tipo}" firmado y subido por invitado externo (${invitado.nombre}).`);
  const postulacion = get(db, 'SELECT responsable_id FROM postulaciones WHERE id = ?', [doc.postulacion_id]);
  notificarSiCorresponde(doc.responsable_id || (postulacion && postulacion.responsable_id), null, doc.postulacion_id,
    'firma_externa_recibida', `${invitado.nombre} subió "${doc.tipo}" firmado.`);
  res.json({ ok: true });
});

// ---------- documentos: acciones ----------
app.post('/api/documentos/:id/marcar-reunido', requireLogin, requireRol('equipo'), (req, res) => {
  const doc = get(db, 'SELECT * FROM documentos WHERE id = ?', [req.params.id]);
  if (!doc) return res.status(404).json({ error: 'No existe' });
  run(db, `UPDATE documentos SET estado = 'reunido' WHERE id = ?`, [doc.id]);
  registrarLog(doc.postulacion_id, req.usuario.id, 'documento_reunido', `"${doc.tipo}" marcado como reunido.`);
  res.json({ ok: true });
});

app.post('/api/documentos/:id/generar-anexo', requireLogin, requireRol('equipo'), async (req, res) => {
  const doc = get(db, 'SELECT * FROM documentos WHERE id = ?', [req.params.id]);
  if (!doc) return res.status(404).json({ error: 'No existe' });
  const postulacion = get(db, 'SELECT * FROM postulaciones WHERE id = ?', [doc.postulacion_id]);
  const convocatoria = get(db, 'SELECT * FROM convocatorias WHERE id = ?', [postulacion.convocatoria_id]);
  const responsable = postulacion.responsable_id ? get(db, 'SELECT nombre FROM usuarios WHERE id=?', [postulacion.responsable_id]) : null;
  postulacion.responsable_nombre = responsable ? responsable.nombre : null;

  const resultado = await ia.generarAnexo({ documento: doc, postulacion, convocatoria });
  // generado_en arranca el plazo de espera del recordatorio automático;
  // recordatorio_enviado_en se limpia para que un borrador regenerado
  // (ej. tras corregirlo) empiece su propio plazo de 48h, no herede el
  // recordatorio ya mandado sobre la versión anterior.
  run(db, `UPDATE documentos SET contenido_generado = ?, generado_en = datetime('now'), recordatorio_enviado_en = NULL WHERE id = ?`,
    [resultado.borrador, doc.id]);
  run(db, `INSERT INTO uso_recursos (tipo, endpoint, postulacion_id, tokens_entrada, tokens_salida, modo, detalle)
           VALUES ('llamada_ia','/api/ia/generar-anexos',?,?,?,?,?)`,
    [postulacion.id, resultado.tokensEntrada || null, resultado.tokensSalida || null, resultado.modo, `Borrador generado para "${doc.tipo}"`]);
  registrarLog(doc.postulacion_id, req.usuario.id, 'anexo_generado', `Borrador de "${doc.tipo}" generado (modo ${resultado.modo}).`);
  res.json({ ok: true, borrador: resultado.borrador, modo: resultado.modo });
});

app.post('/api/documentos/:id/aprobar-anexo', requireLogin, requireRol('equipo'), (req, res) => {
  const doc = get(db, 'SELECT * FROM documentos WHERE id = ?', [req.params.id]);
  if (!doc) return res.status(404).json({ error: 'No existe' });
  if (!doc.contenido_generado) return res.status(400).json({ error: 'Primero hay que generar el borrador.' });
  if (doc.requiere_firma_externa && doc.estado_firma !== 'firmada') {
    run(db, `UPDATE documentos SET estado_firma = 'pendiente' WHERE id = ?`, [doc.id]);
    registrarLog(doc.postulacion_id, req.usuario.id, 'anexo_aprobado', `"${doc.tipo}" aprobado por el equipo — queda pendiente de firma externa antes de contar como reunido.`);
    return res.json({ ok: true, reunido: false });
  }
  run(db, `UPDATE documentos SET estado = 'reunido' WHERE id = ?`, [doc.id]);
  registrarLog(doc.postulacion_id, req.usuario.id, 'anexo_aprobado', `"${doc.tipo}" aprobado por el equipo — queda reunido.`);
  res.json({ ok: true, reunido: true });
});

app.post('/api/documentos/:id/marcar-firmada', requireLogin, requireRol('equipo'), (req, res) => {
  const doc = get(db, 'SELECT * FROM documentos WHERE id = ?', [req.params.id]);
  if (!doc) return res.status(404).json({ error: 'No existe' });
  run(db, `UPDATE documentos SET estado_firma = 'firmada', estado = 'reunido' WHERE id = ?`, [doc.id]);
  registrarLog(doc.postulacion_id, req.usuario.id, 'firma_externa_registrada', `Firma externa de "${doc.tipo}" registrada — queda reunido.`);
  res.json({ ok: true });
});

app.get('/api/documentos/:id/descargar-borrador', requireLogin, async (req, res) => {
  const doc = get(db, 'SELECT * FROM documentos WHERE id = ?', [req.params.id]);
  if (!doc || !doc.contenido_generado) return res.status(404).json({ error: 'No hay borrador generado para este documento.' });
  const postulacion = get(db, 'SELECT * FROM postulaciones WHERE id = ?', [doc.postulacion_id]);
  const convocatoria = get(db, 'SELECT * FROM convocatorias WHERE id = ?', [postulacion.convocatoria_id]);
  const buffer = await borradorADocx({
    titulo: doc.tipo,
    subtitulo: `${convocatoria.titulo} · ${convocatoria.fuente}`,
    cuerpo: doc.contenido_generado,
  });
  const nombre = doc.tipo.replace(/[^a-zA-Z0-9]+/g, '-').toLowerCase().slice(0, 60);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
  res.setHeader('Content-Disposition', `attachment; filename="${nombre}.docx"`);
  res.send(buffer);
});

app.post('/api/documentos/:id/subir-archivo', requireLogin, requireRol('equipo'), upload.single('archivo'), (req, res) => {
  const doc = get(db, 'SELECT * FROM documentos WHERE id = ?', [req.params.id]);
  if (!doc) return res.status(404).json({ error: 'No existe' });
  if (!req.file) return res.status(400).json({ error: 'No se recibió ningún archivo.' });

  const urlPublica = `/uploads/${req.file.filename}`;
  // Cada subida queda como una fila nueva en documento_versiones (append-only)
  // en vez de solo pisar documentos.archivo_url — así no desaparece sin
  // rastro la versión anterior (ej. el certificado vencido que motivó la
  // auditoría) cuando se sube la versión corregida.
  run(db, 'INSERT INTO documento_versiones (documento_id, archivo_url, nombre_original, subido_por) VALUES (?,?,?,?)',
    [doc.id, urlPublica, req.file.originalname, req.usuario.id]);

  if (doc.requiere_firma_externa) {
    run(db, `UPDATE documentos SET archivo_url = ?, estado_firma = 'firmada', estado = 'reunido' WHERE id = ?`, [urlPublica, doc.id]);
    registrarLog(doc.postulacion_id, req.usuario.id, 'archivo_subido', `Versión firmada de "${doc.tipo}" subida (${req.file.originalname}) — queda reunido.`);
  } else {
    run(db, `UPDATE documentos SET archivo_url = ?, estado = 'reunido' WHERE id = ?`, [urlPublica, doc.id]);
    registrarLog(doc.postulacion_id, req.usuario.id, 'archivo_subido', `"${doc.tipo}" reunido con el archivo ${req.file.originalname}.`);
  }
  res.json({ ok: true, archivo_url: urlPublica });
});

app.get('/api/documentos/:id/versiones', requireLogin, (req, res) => {
  const doc = get(db, 'SELECT * FROM documentos WHERE id = ?', [req.params.id]);
  if (!doc) return res.status(404).json({ error: 'No existe' });
  const versiones = all(db, `
    SELECT dv.*, u.nombre AS subido_por_nombre FROM documento_versiones dv
    LEFT JOIN usuarios u ON u.id = dv.subido_por
    WHERE dv.documento_id = ? ORDER BY dv.id DESC`, [doc.id]);
  res.json(versiones);
});

app.post('/api/documentos/:id/auditar', requireLogin, requireRol('equipo'), async (req, res) => {
  const doc = get(db, 'SELECT * FROM documentos WHERE id = ?', [req.params.id]);
  if (!doc) return res.status(404).json({ error: 'No existe' });
  const postulacion = get(db, 'SELECT * FROM postulaciones WHERE id = ?', [doc.postulacion_id]);
  const convocatoria = get(db, 'SELECT * FROM convocatorias WHERE id = ?', [postulacion.convocatoria_id]);

  const resultado = await ia.auditarDocumento({ documento: doc, postulacion, convocatoria });
  run(db, `UPDATE documentos SET estado_auditoria = ?, detalle_auditoria = ? WHERE id = ?`,
    [resultado.estado, resultado.detalle, doc.id]);
  run(db, `INSERT INTO uso_recursos (tipo, endpoint, postulacion_id, tokens_entrada, tokens_salida, modo, detalle)
           VALUES ('llamada_ia','/api/ia/auditar-documentos',?,?,?,?,?)`,
    [postulacion.id, resultado.tokensEntrada || null, resultado.tokensSalida || null, resultado.modo, `Auditoría de "${doc.tipo}": ${resultado.estado}`]);
  registrarLog(doc.postulacion_id, req.usuario.id, 'documento_auditado', `"${doc.tipo}" → ${resultado.estado} (modo ${resultado.modo}).`);
  // Un no_cumple/falta es justo el tipo de cosa que no debería descubrirse
  // solo mirando el tablero — avisa a quien esté a cargo del documento (o,
  // si no hay nadie asignado, a quien esté a cargo de toda la postulación).
  if (resultado.estado === 'no_cumple' || resultado.estado === 'falta') {
    const destino = doc.responsable_id || postulacion.responsable_id;
    notificarSiCorresponde(destino, req.usuario.id, doc.postulacion_id, 'auditoria_con_problema',
      `"${doc.tipo}" quedó en auditoría "${resultado.estado === 'no_cumple' ? 'no cumple' : 'falta'}" en ${convocatoria.titulo}.`);
  }
  res.json({ ok: true, ...resultado });
});

// ---------- documentos: asignar responsable (función de gestión de proyecto) ----------
app.post('/api/documentos/:id/asignar', requireLogin, requireRol('equipo', 'director'), (req, res) => {
  const doc = get(db, 'SELECT * FROM documentos WHERE id = ?', [req.params.id]);
  if (!doc) return res.status(404).json({ error: 'No existe' });
  const { responsable_id } = req.body || {};
  const idNum = responsable_id ? Number(responsable_id) : null;
  if (idNum) {
    const u = get(db, `SELECT id, nombre FROM usuarios WHERE id = ? AND rol = 'equipo'`, [idNum]);
    if (!u) return res.status(400).json({ error: 'Ese usuario no existe o no es del equipo.' });
    run(db, 'UPDATE documentos SET responsable_id = ? WHERE id = ?', [idNum, doc.id]);
    registrarLog(doc.postulacion_id, req.usuario.id, 'documento_asignado', `"${doc.tipo}" asignado a ${u.nombre}.`);
    notificarSiCorresponde(idNum, req.usuario.id, doc.postulacion_id, 'documento_asignado',
      `Te asignaron "${doc.tipo}".`);
  } else {
    run(db, 'UPDATE documentos SET responsable_id = NULL WHERE id = ?', [doc.id]);
    registrarLog(doc.postulacion_id, req.usuario.id, 'documento_desasignado', `"${doc.tipo}" quedó sin responsable asignado.`);
  }
  res.json({ ok: true });
});

// ---------- comentarios (postulación completa, o un documento puntual) ----------
app.post('/api/postulaciones/:id/comentarios', requireLogin, (req, res) => {
  const postulacion = get(db, 'SELECT * FROM postulaciones WHERE id = ?', [req.params.id]);
  if (!postulacion) return res.status(404).json({ error: 'No existe' });
  const texto = (req.body && req.body.texto || '').trim();
  if (!texto) return res.status(400).json({ error: 'El comentario no puede ir vacío.' });
  const documentoId = req.body && req.body.documento_id ? Number(req.body.documento_id) : null;
  let doc = null;
  if (documentoId) {
    doc = get(db, 'SELECT * FROM documentos WHERE id = ? AND postulacion_id = ?', [documentoId, postulacion.id]);
    if (!doc) return res.status(400).json({ error: 'Ese documento no pertenece a esta postulación.' });
  }
  const r = run(db, 'INSERT INTO comentarios (postulacion_id, documento_id, usuario_id, texto) VALUES (?,?,?,?)',
    [postulacion.id, documentoId, req.usuario.id, texto]);
  registrarLog(postulacion.id, req.usuario.id, 'comentario_agregado',
    doc ? `Comentó en "${doc.tipo}": ${texto.slice(0, 80)}${texto.length > 80 ? '…' : ''}` : `Comentó: ${texto.slice(0, 80)}${texto.length > 80 ? '…' : ''}`);
  // Avisa a quien esté más cerca del comentario: el responsable del
  // documento si el comentario fue sobre uno puntual, y siempre al
  // responsable de la postulación completa (salvo que sea la misma persona
  // que comentó, o ya se le haya avisado como responsable del documento).
  const avisados = new Set([req.usuario.id]);
  if (doc && doc.responsable_id && !avisados.has(doc.responsable_id)) {
    notificarSiCorresponde(doc.responsable_id, req.usuario.id, postulacion.id, 'comentario_nuevo',
      `${req.usuario.nombre} comentó en "${doc.tipo}".`);
    avisados.add(doc.responsable_id);
  }
  if (postulacion.responsable_id && !avisados.has(postulacion.responsable_id)) {
    notificarSiCorresponde(postulacion.responsable_id, req.usuario.id, postulacion.id, 'comentario_nuevo',
      `${req.usuario.nombre} comentó en la postulación.`);
  }
  const usuario = get(db, 'SELECT nombre FROM usuarios WHERE id = ?', [req.usuario.id]);
  res.json({ ok: true, comentario: { id: r.lastInsertRowid, postulacion_id: postulacion.id, documento_id: documentoId, usuario_id: req.usuario.id, usuario_nombre: usuario.nombre, texto, creado_en: new Date().toISOString() } });
});

// ---------- panel del equipo ----------
app.get('/api/panel-equipo', requireLogin, requireRol('equipo'), (req, res) => {
  revisarRecordatoriosPendientes();
  const postulaciones = all(db, `
    SELECT p.*, c.titulo AS convocatoria_titulo, c.fuente AS convocatoria_fuente,
           u.nombre AS responsable_nombre
    FROM postulaciones p
    JOIN convocatorias c ON c.id = p.convocatoria_id
    LEFT JOIN usuarios u ON u.id = p.responsable_id
    ORDER BY p.etapa_actual`).map(postulacionConSemaforo);

  const notificaciones = all(db, `
    SELECT n.*, p.id AS postulacion_id FROM notificaciones n
    LEFT JOIN postulaciones p ON p.id = n.postulacion_id
    WHERE n.usuario_id = ? ORDER BY n.id DESC`, [req.usuario.id]);

  res.json({ postulaciones, notificaciones, documentos: documentosDeTodas() });
});

app.post('/api/notificaciones/:id/leida', requireLogin, (req, res) => {
  run(db, 'UPDATE notificaciones SET leida = 1 WHERE id = ? AND usuario_id = ?', [req.params.id, req.usuario.id]);
  res.json({ ok: true });
});

// ---------- panel del director ----------
app.get('/api/panel-director', requireLogin, requireRol('director'), (req, res) => {
  revisarRecordatoriosPendientes();
  const postulaciones = all(db, `
    SELECT p.*, c.titulo AS convocatoria_titulo, c.fuente AS convocatoria_fuente,
           u.nombre AS responsable_nombre
    FROM postulaciones p
    JOIN convocatorias c ON c.id = p.convocatoria_id
    LEFT JOIN usuarios u ON u.id = p.responsable_id
    ORDER BY p.id`).map(postulacionConSemaforo);

  const activas = postulaciones.filter((p) => p.resultado === 'en_curso');
  const conteo = { verde: 0, ambar: 0, rojo: 0 };
  for (const p of activas) conteo[p.semaforo]++;

  const atencionInmediata = activas.filter((p) => p.semaforo === 'rojo' && p.escalada_director);

  const documentosProblema = all(db, `
    SELECT d.*, p.id AS postulacion_id, c.titulo AS convocatoria_titulo
    FROM documentos d
    JOIN postulaciones p ON p.id = d.postulacion_id
    JOIN convocatorias c ON c.id = p.convocatoria_id
    WHERE d.estado_auditoria IN ('no_cumple','falta')`);

  const sinResponsable = activas.filter((p) => !p.responsable_id);
  const sinFecha = activas.filter((p) => !p.proximo_hito_fecha);

  const puntosDeAtencion = {
    documentos_con_problema: documentosProblema.length,
    postulaciones_sin_responsable: sinResponsable.length,
    postulaciones_sin_fecha: sinFecha.length,
    detalle_documentos: documentosProblema,
  };

  const uso = all(db, 'SELECT * FROM uso_recursos ORDER BY id DESC');
  const costoTotal = uso.reduce((s, u) => s + (u.costo_estimado_usd || 0), 0);
  const porEndpoint = {};
  for (const u of uso) porEndpoint[u.endpoint] = (porEndpoint[u.endpoint] || 0) + (u.costo_estimado_usd || 0);

  const resueltas = postulaciones.filter((p) => p.resultado !== 'en_curso');
  const adjudicadas = resueltas.filter((p) => p.resultado === 'adjudicada');
  const tasaAdjudicacion = resueltas.length ? Math.round((adjudicadas.length / resueltas.length) * 100) : null;
  // La etiqueta en pantalla ya decía "(año en curso)" pero el cálculo sumaba
  // TODAS las adjudicadas sin filtrar por año — se corrige acá, de paso
  // necesario para que la meta anual (más abajo) compare peras con peras.
  const anioActual = new Date().getFullYear();
  const adjudicadasEsteAnio = adjudicadas.filter((p) => p.fecha_resultado && p.fecha_resultado.slice(0, 4) === String(anioActual));
  const montoAdjudicadoTotal = adjudicadasEsteAnio.reduce((s, p) => s + (p.monto_adjudicado || 0), 0);
  const montoSolicitadoAdjudicadas = adjudicadas.reduce((s, p) => s + (p.monto_solicitado || 0), 0);

  const metaRow = get(db, 'SELECT * FROM metas_anuales WHERE anio = ?', [anioActual]);
  const meta = {
    anio: anioActual,
    monto_meta: metaRow ? metaRow.monto_meta : null,
    monto_adjudicado: montoAdjudicadoTotal,
    porcentaje: metaRow && metaRow.monto_meta ? Math.round((montoAdjudicadoTotal / metaRow.monto_meta) * 100) : null,
  };

  const embudo = {};
  for (let e = 1; e <= 7; e++) embudo[e] = activas.filter((p) => p.etapa_actual === e).length;

  // Look-ahead 3 semanas
  const hoy = new Date(); hoy.setHours(0, 0, 0, 0);
  const semanas = [[], [], []];
  const restricciones = [];
  for (const p of activas) {
    if (!p.responsable_id) {
      restricciones.push({ tipo: 'Sin responsable', postulacion: p.convocatoria_titulo, postulacion_id: p.id });
      continue;
    }
    if (!p.proximo_hito_fecha) {
      restricciones.push({ tipo: 'Sin fecha', postulacion: p.convocatoria_titulo, postulacion_id: p.id });
      continue;
    }
    const dias = Math.round((new Date(p.proximo_hito_fecha + 'T00:00:00') - hoy) / 86400000);
    if (dias < 0) continue;
    const semanaIdx = Math.floor(dias / 7);
    if (semanaIdx <= 2) {
      semanas[semanaIdx].push({ postulacion: p.convocatoria_titulo, postulacion_id: p.id, hito: p.proximo_hito, fecha: p.proximo_hito_fecha });
    }
  }

  // El director también puede recibir notificaciones (ej. si queda como
  // responsable de una postulación, o si le comentan directo un documento)
  // — antes solo panel-equipo mostraba esta tabla, aunque cualquier usuario
  // podía terminar con filas propias en `notificaciones`.
  const notificaciones = all(db, `
    SELECT n.*, p.id AS postulacion_id FROM notificaciones n
    LEFT JOIN postulaciones p ON p.id = n.postulacion_id
    WHERE n.usuario_id = ? ORDER BY n.id DESC`, [req.usuario.id]);

  res.json({
    conteo, atencionInmediata, puntosDeAtencion, notificaciones, meta,
    costos: { total: costoTotal, porEndpoint, llamadas: uso.length, modoReal: ia.tieneApiKeyReal() },
    kpis: { tasaAdjudicacion, montoAdjudicadoTotal, montoSolicitadoAdjudicadas, embudo, totalActivas: activas.length },
    lookAhead: { semanas, restricciones },
    postulaciones: activas,
    documentos: documentosDeTodas(),
  });
});

// ---------- meta anual de monto adjudicado ----------
app.post('/api/meta-anual', requireLogin, requireRol('director'), (req, res) => {
  const anio = new Date().getFullYear();
  const montoMeta = Number(req.body.monto_meta);
  if (!Number.isFinite(montoMeta) || montoMeta <= 0) {
    return res.status(400).json({ error: 'Ingresa un monto meta válido (mayor a 0).' });
  }
  const existente = get(db, 'SELECT * FROM metas_anuales WHERE anio = ?', [anio]);
  if (existente) {
    run(db, `UPDATE metas_anuales SET monto_meta = ?, actualizado_por = ?, actualizado_en = datetime('now') WHERE id = ?`,
      [montoMeta, req.usuario.id, existente.id]);
  } else {
    run(db, 'INSERT INTO metas_anuales (anio, monto_meta, actualizado_por) VALUES (?,?,?)', [anio, montoMeta, req.usuario.id]);
  }
  registrarLog(null, req.usuario.id, 'meta_anual_actualizada', `Meta ${anio} actualizada a $${montoMeta.toLocaleString('es-CL')}.`);
  res.json({ ok: true });
});

// ---------- plantillas de checklist (reutilizar entre postulaciones) ----------
app.get('/api/plantillas', requireLogin, (req, res) => {
  const plantillas = all(db, `
    SELECT pl.*, u.nombre AS creado_por_nombre,
           (SELECT COUNT(*) FROM plantilla_documentos pd WHERE pd.plantilla_id = pl.id) AS n_documentos
    FROM plantillas_checklist pl
    LEFT JOIN usuarios u ON u.id = pl.creado_por
    ORDER BY pl.id DESC`);
  res.json(plantillas);
});

app.get('/api/plantillas/:id', requireLogin, (req, res) => {
  const plantilla = get(db, 'SELECT * FROM plantillas_checklist WHERE id = ?', [req.params.id]);
  if (!plantilla) return res.status(404).json({ error: 'No existe' });
  const documentos = all(db, 'SELECT * FROM plantilla_documentos WHERE plantilla_id = ? ORDER BY orden, id', [plantilla.id]);
  res.json({ ...plantilla, documentos });
});

// Convierte el checklist ya cargado de una postulación en una plantilla
// reutilizable — más rápido que armar una desde cero, y parte de datos
// reales en vez de una lista genérica inventada.
app.post('/api/postulaciones/:id/guardar-como-plantilla', requireLogin, requireRol('equipo'), (req, res) => {
  const postulacion = get(db, 'SELECT * FROM postulaciones WHERE id = ?', [req.params.id]);
  if (!postulacion) return res.status(404).json({ error: 'No existe' });
  const nombre = (req.body && req.body.nombre || '').trim();
  if (!nombre) return res.status(400).json({ error: 'Falta el nombre de la plantilla.' });
  const descripcion = (req.body && req.body.descripcion || '').trim() || null;
  const documentos = all(db, 'SELECT * FROM documentos WHERE postulacion_id = ? ORDER BY id', [postulacion.id]);
  if (!documentos.length) return res.status(400).json({ error: 'Esta postulación todavía no tiene checklist.' });

  const r = run(db, 'INSERT INTO plantillas_checklist (nombre, descripcion, creado_por) VALUES (?,?,?)',
    [nombre, descripcion, req.usuario.id]);
  const plantillaId = r.lastInsertRowid;
  documentos.forEach((d, i) => {
    run(db, `INSERT INTO plantilla_documentos (plantilla_id, tipo, requisito, origen, requiere_firma_externa, sensible, fase, orden)
             VALUES (?,?,?,?,?,?,?,?)`,
      [plantillaId, d.tipo, d.requisito, d.origen, d.requiere_firma_externa, d.sensible, d.fase, i]);
  });
  registrarLog(postulacion.id, req.usuario.id, 'plantilla_creada', `Checklist guardado como plantilla "${nombre}" (${documentos.length} documentos).`);
  res.json({ ok: true, plantilla_id: plantillaId, n_documentos: documentos.length });
});

// Aplica una plantilla a una postulación — agrega los documentos que
// todavía no existan ahí (por tipo), sin duplicar los que ya estaban.
app.post('/api/plantillas/:id/aplicar', requireLogin, requireRol('equipo'), (req, res) => {
  const plantilla = get(db, 'SELECT * FROM plantillas_checklist WHERE id = ?', [req.params.id]);
  if (!plantilla) return res.status(404).json({ error: 'No existe' });
  const postulacionId = req.body && req.body.postulacion_id ? Number(req.body.postulacion_id) : null;
  const postulacion = postulacionId ? get(db, 'SELECT * FROM postulaciones WHERE id = ?', [postulacionId]) : null;
  if (!postulacion) return res.status(400).json({ error: 'Falta indicar a qué postulación aplicar la plantilla.' });

  const documentosPlantilla = all(db, 'SELECT * FROM plantilla_documentos WHERE plantilla_id = ? ORDER BY orden, id', [plantilla.id]);
  const existentes = new Set(all(db, 'SELECT tipo FROM documentos WHERE postulacion_id = ?', [postulacion.id]).map((d) => d.tipo));
  let agregados = 0;
  for (const pd of documentosPlantilla) {
    if (existentes.has(pd.tipo)) continue;
    run(db, `INSERT INTO documentos (postulacion_id, tipo, estado, origen, requiere_firma_externa, estado_firma, estado_auditoria, requisito, sensible, fase)
             VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [postulacion.id, pd.tipo, 'pendiente', pd.origen, pd.requiere_firma_externa, 'no_aplica', 'sin_auditar', pd.requisito, pd.sensible, pd.fase]);
    agregados++;
  }
  registrarLog(postulacion.id, req.usuario.id, 'plantilla_aplicada', `Plantilla "${plantilla.nombre}" aplicada — ${agregados} documentos nuevos agregados (${documentosPlantilla.length - agregados} ya existían).`);
  res.json({ ok: true, agregados, ya_existian: documentosPlantilla.length - agregados });
});

// ---------- administración / Configuración ----------
// Guardado por PERMISO (gestionar_usuarios), no por rol fijo -- admin y
// director lo traen de fábrica, pero alguien de "equipo" puede tenerlo
// también vía una excepción en usuario_permisos (ver tienePermiso arriba).
const ROLES_VALIDOS = ['admin', 'director', 'equipo'];

function generarPasswordTemporal() {
  // 12 caracteres alfanuméricos -- pasa el mínimo de 8 de la política NIST
  // sin problema; igual queda marcada debe_cambiar_password=1, así que es
  // de un solo uso por diseño, no hace falta que sea memorable.
  return crypto.randomBytes(9).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 12);
}

function usuarioConPermisos(u) {
  return {
    id: u.id, nombre: u.nombre, email: u.email, rol: u.rol, activo: !!u.activo,
    debe_cambiar_password: !!u.debe_cambiar_password, totp_habilitado: !!u.totp_habilitado,
    creado_en: u.creado_en,
    gestionar_usuarios: tienePermiso(u, 'gestionar_usuarios'),
    gestionar_usuarios_excepcion: !!get(db, 'SELECT 1 FROM usuario_permisos WHERE usuario_id = ? AND permiso = ?', [u.id, 'gestionar_usuarios']),
  };
}

app.get('/api/administracion', requireLogin, requirePermiso('gestionar_usuarios'), (req, res) => {
  const usuarios = all(db, 'SELECT * FROM usuarios ORDER BY activo DESC, rol DESC, nombre').map(usuarioConPermisos);
  res.json({
    usuarios,
    umbrales: {
      dias_ambar_semaforo: 5,
      presupuesto_mensual_claude_usd: 25,
      tope_paginas_documento: 30,
      umbral_escalamiento_director: 'pendiente de definir',
      muestra_aleatoria_segunda_revision: 'pendiente de definir',
    },
  });
});

// Crear usuario -- ciclo de vida (3.2): password temporal + debe_cambiar_password=1
// + totp_habilitado=0, así que la persona pasa por el mismo enrolamiento
// forzado de cambio de clave + 2FA que ya prueba el resto del sistema.
// La contraseña temporal se devuelve en texto plano UNA sola vez, para que
// el admin se la pase por un canal aparte (nunca queda guardada en claro).
app.post('/api/administracion/usuarios', requireLogin, requirePermiso('gestionar_usuarios'), (req, res) => {
  const { nombre, email, rol } = req.body || {};
  const emailNormalizado = (email || '').toLowerCase().trim();
  if (!nombre || !nombre.trim()) return res.status(400).json({ error: 'El nombre es obligatorio.' });
  if (!emailNormalizado) return res.status(400).json({ error: 'El correo es obligatorio.' });
  if (!ROLES_VALIDOS.includes(rol)) return res.status(400).json({ error: `Rol inválido. Debe ser uno de: ${ROLES_VALIDOS.join(', ')}.` });
  if (get(db, 'SELECT id FROM usuarios WHERE email = ?', [emailNormalizado])) {
    return res.status(400).json({ error: 'Ya existe un usuario con ese correo.' });
  }

  const passwordTemporal = generarPasswordTemporal();
  const hash = bcrypt.hashSync(passwordTemporal, 10);
  const resultado = run(db, `INSERT INTO usuarios (nombre, email, rol, password_hash, debe_cambiar_password)
    VALUES (?,?,?,?,1)`, [nombre.trim(), emailNormalizado, rol, hash]);
  const nuevoId = resultado.lastInsertRowid;
  registrarLogSeguridad(nuevoId, 'cuenta_creada', `Creada por ${req.usuario.nombre} (rol: ${rol}).`, req.ip);
  const usuario = get(db, 'SELECT * FROM usuarios WHERE id = ?', [nuevoId]);
  res.json({ ok: true, usuario: usuarioConPermisos(usuario), passwordTemporal });
});

// Cambiar rol -- sin límite de cuántas personas pueden tener el mismo rol
// (3.2: "puede haber varios director a la vez"). Nadie puede cambiarse el
// rol a sí mismo -- evita que alguien se autopromueva o se quite permisos
// sin querer y quede bloqueado.
app.patch('/api/administracion/usuarios/:id/rol', requireLogin, requirePermiso('gestionar_usuarios'), (req, res) => {
  const id = Number(req.params.id);
  if (id === req.usuario.id) return res.status(400).json({ error: 'No puedes cambiar tu propio rol.' });
  const { rol } = req.body || {};
  if (!ROLES_VALIDOS.includes(rol)) return res.status(400).json({ error: `Rol inválido. Debe ser uno de: ${ROLES_VALIDOS.join(', ')}.` });
  const objetivo = get(db, 'SELECT * FROM usuarios WHERE id = ?', [id]);
  if (!objetivo) return res.status(404).json({ error: 'Usuario no encontrado.' });
  run(db, 'UPDATE usuarios SET rol = ? WHERE id = ?', [rol, id]);
  registrarLogSeguridad(id, 'cambio_rol', `${req.usuario.nombre} cambió el rol de "${objetivo.rol}" a "${rol}".`, req.ip);
  res.json({ ok: true });
});

// Excepción de permiso puntual sobre el default del rol (usuario_permisos).
// otorgado: true (dar el permiso aunque el rol no lo traiga), false (quitarlo
// aunque el rol sí lo traiga por defecto), null (borrar la excepción, volver
// a lo que diga el rol). Igual que el cambio de rol, no se puede aplicar a
// la propia cuenta.
app.patch('/api/administracion/usuarios/:id/permisos', requireLogin, requirePermiso('gestionar_usuarios'), (req, res) => {
  const id = Number(req.params.id);
  if (id === req.usuario.id) return res.status(400).json({ error: 'No puedes cambiar tus propios permisos.' });
  const { permiso, otorgado } = req.body || {};
  if (permiso !== 'gestionar_usuarios') return res.status(400).json({ error: 'Permiso desconocido.' });
  const objetivo = get(db, 'SELECT * FROM usuarios WHERE id = ?', [id]);
  if (!objetivo) return res.status(404).json({ error: 'Usuario no encontrado.' });

  if (otorgado === null) {
    run(db, 'DELETE FROM usuario_permisos WHERE usuario_id = ? AND permiso = ?', [id, permiso]);
    registrarLogSeguridad(id, 'cambio_rol', `${req.usuario.nombre} quitó la excepción de permiso "${permiso}" (vuelve al default del rol).`, req.ip);
  } else {
    const existente = get(db, 'SELECT id FROM usuario_permisos WHERE usuario_id = ? AND permiso = ?', [id, permiso]);
    if (existente) {
      run(db, 'UPDATE usuario_permisos SET otorgado = ? WHERE id = ?', [otorgado ? 1 : 0, existente.id]);
    } else {
      run(db, 'INSERT INTO usuario_permisos (usuario_id, permiso, otorgado) VALUES (?,?,?)', [id, permiso, otorgado ? 1 : 0]);
    }
    registrarLogSeguridad(id, 'cambio_rol', `${req.usuario.nombre} ${otorgado ? 'otorgó' : 'quitó'} el permiso "${permiso}" como excepción puntual.`, req.ip);
  }
  res.json({ ok: true });
});

// Desactivar / reactivar -- "desactivar, no borrar" (3.2): borrar rompería
// log_eventos.usuario_id, documentos.responsable_id y notificaciones.usuario_id,
// que siguen apuntando a esta fila. No se puede desactivar la propia cuenta.
app.post('/api/administracion/usuarios/:id/desactivar', requireLogin, requirePermiso('gestionar_usuarios'), (req, res) => {
  const id = Number(req.params.id);
  if (id === req.usuario.id) return res.status(400).json({ error: 'No puedes desactivar tu propia cuenta.' });
  const objetivo = get(db, 'SELECT * FROM usuarios WHERE id = ?', [id]);
  if (!objetivo) return res.status(404).json({ error: 'Usuario no encontrado.' });
  run(db, 'UPDATE usuarios SET activo = 0 WHERE id = ?', [id]);
  registrarLogSeguridad(id, 'cuenta_desactivada', `Desactivada por ${req.usuario.nombre}.`, req.ip);
  res.json({ ok: true });
});

app.post('/api/administracion/usuarios/:id/reactivar', requireLogin, requirePermiso('gestionar_usuarios'), (req, res) => {
  const id = Number(req.params.id);
  const objetivo = get(db, 'SELECT * FROM usuarios WHERE id = ?', [id]);
  if (!objetivo) return res.status(404).json({ error: 'Usuario no encontrado.' });
  run(db, 'UPDATE usuarios SET activo = 1, intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?', [id]);
  registrarLogSeguridad(id, 'cuenta_reactivada', `Reactivada por ${req.usuario.nombre}.`, req.ip);
  res.json({ ok: true });
});

// Reseteo de contraseña por un admin -- para cuando alguien queda fuera de
// su cuenta y no puede usar el cambio de contraseña de autoservicio
// (/api/cambiar-password, que pide la clave actual). Misma lógica que crear
// usuario: password temporal en texto plano, una sola vez, y queda forzado
// el cambio en el próximo login.
app.post('/api/administracion/usuarios/:id/resetear-password', requireLogin, requirePermiso('gestionar_usuarios'), (req, res) => {
  const id = Number(req.params.id);
  if (id === req.usuario.id) return res.status(400).json({ error: 'Usa "Cambiar mi contraseña" para tu propia cuenta.' });
  const objetivo = get(db, 'SELECT * FROM usuarios WHERE id = ?', [id]);
  if (!objetivo) return res.status(404).json({ error: 'Usuario no encontrado.' });
  const passwordTemporal = generarPasswordTemporal();
  const hash = bcrypt.hashSync(passwordTemporal, 10);
  run(db, `UPDATE usuarios SET password_hash = ?, debe_cambiar_password = 1, password_actualizada_en = NULL,
           intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?`, [hash, id]);
  registrarLogSeguridad(id, 'cambio_password', `Reseteada por ${req.usuario.nombre} (contraseña temporal).`, req.ip);
  res.json({ ok: true, passwordTemporal });
});

// Reseteo de 2FA -- para cuando alguien pierde el teléfono Y ya gastó todos
// sus códigos de respaldo (la única otra vía de recuperación). Borra el
// secreto y todos los códigos de respaldo existentes; el gate de
// requireLogin ya se encarga de exigir un enrolamiento nuevo en el próximo
// login, no hace falta tocar debe_cambiar_password para esto.
app.post('/api/administracion/usuarios/:id/resetear-2fa', requireLogin, requirePermiso('gestionar_usuarios'), (req, res) => {
  const id = Number(req.params.id);
  if (id === req.usuario.id) return res.status(400).json({ error: 'No puedes resetear tu propio 2FA desde acá.' });
  const objetivo = get(db, 'SELECT * FROM usuarios WHERE id = ?', [id]);
  if (!objetivo) return res.status(404).json({ error: 'Usuario no encontrado.' });
  run(db, 'UPDATE usuarios SET totp_habilitado = 0, totp_secret = NULL WHERE id = ?', [id]);
  run(db, 'DELETE FROM totp_codigos_respaldo WHERE usuario_id = ?', [id]);
  registrarLogSeguridad(id, 'totp_reseteado', `2FA reseteado por ${req.usuario.nombre} -- deberá enrolarse de nuevo.`, req.ip);
  res.json({ ok: true });
});

// Log de seguridad -- eventos de autenticación/administración (login,
// bloqueos, cambios de rol/permiso, altas/bajas de cuenta), separado de
// log_eventos porque ese es por postulación puntual y este es transversal.
app.get('/api/administracion/log-seguridad', requireLogin, requirePermiso('gestionar_usuarios'), (req, res) => {
  const eventos = all(db, `
    SELECT ls.id, ls.accion, ls.detalle, ls.ip, ls.creado_en, u.nombre AS usuario_nombre, u.email AS usuario_email
    FROM log_seguridad ls
    LEFT JOIN usuarios u ON u.id = ls.usuario_id
    ORDER BY ls.id DESC LIMIT 200`);
  res.json({ eventos });
});

app.use(express.static(path.join(__dirname, '..', 'public')));
app.use('/uploads', requireLoginRedirect, express.static(UPLOADS_DIR));

app.listen(PORT, () => {
  console.log(`panel-postulaciones escuchando en http://localhost:${PORT}`);
  console.log(ia.tieneApiKeyReal() ? 'Modo IA: REAL (ANTHROPIC_API_KEY configurada)' : 'Modo IA: DEMO (sin ANTHROPIC_API_KEY, resultados sintéticos)');
});
