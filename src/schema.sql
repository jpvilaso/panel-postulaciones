-- Esquema completo desde el día 1 (Parte 1 de plan-implementacion.md),
-- incluye columnas que recién usa la Parte 3.6 para no migrar la tabla dos veces.

-- Ampliada 2026-08-04 (login con roles + 2FA, arquitectura sección 3.2):
-- 4 roles (admin/director/equipo -- invitado sigue siendo el token sin
-- cuenta de la tabla `invitados`, no una fila acá), ciclo de vida completo
-- de una cuenta (activo en vez de borrar), 2FA con TOTP, y proteccion
-- contra fuerza bruta. La politica de contraseña sigue NIST SP 800-63B
-- Rev 4 (sin rotacion forzada por calendario -- password_actualizada_en es
-- solo auditoria de cuando fue el ultimo cambio, no dispara nada solo).
CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  rol TEXT NOT NULL CHECK (rol IN ('admin', 'director', 'equipo')),
  password_hash TEXT NOT NULL,
  -- true al crear la cuenta -- el primer login fuerza cambio de clave +
  -- enrolamiento de 2FA antes de dejar entrar a cualquier otra pantalla.
  debe_cambiar_password INTEGER NOT NULL DEFAULT 1,
  password_actualizada_en TEXT,
  totp_secret TEXT,
  totp_habilitado INTEGER NOT NULL DEFAULT 0,
  -- Fuerza bruta: 5 intentos fallidos (login o TOTP) -> bloqueo temporal de
  -- 15 min (no indefinido), con backoff creciente si se repite.
  intentos_fallidos INTEGER NOT NULL DEFAULT 0,
  bloqueado_hasta TEXT,
  -- Alguien que sale del equipo se DESACTIVA, nunca se borra -- borrar
  -- rompería log_eventos.usuario_id, documentos.responsable_id y
  -- notificaciones.usuario_id, que siguen apuntando a esta fila.
  activo INTEGER NOT NULL DEFAULT 1,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Excepciones de permisos por persona, sobre el default de su rol (ej. dar
-- a alguien de "equipo" el permiso de gestionar usuarios sin volverlo
-- "director"). Sin fila para un permiso = usa el default del rol (ver
-- PERMISOS_POR_ROL en el backend). admin/director traen gestionar_usuarios
-- activado de fábrica y no necesitan fila acá para eso.
CREATE TABLE IF NOT EXISTS usuario_permisos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
  permiso TEXT NOT NULL,
  otorgado INTEGER NOT NULL DEFAULT 1,
  UNIQUE(usuario_id, permiso)
);

-- Códigos de recuperación del 2FA -- 8-10 por persona, generados al activar
-- el TOTP, de un solo uso, guardados con hash (nunca en texto plano). Sin
-- esto, perder el celular con el authenticator deja la cuenta sin forma de
-- recuperarse.
CREATE TABLE IF NOT EXISTS totp_codigos_respaldo (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
  codigo_hash TEXT NOT NULL,
  usado INTEGER NOT NULL DEFAULT 0,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Eventos de autenticación/administración -- transversal, no depende de
-- estar viendo una postulación puntual (a diferencia de log_eventos, que sí
-- es por postulación). usuario_id nullable porque un intento de login con
-- un email que no existe no tiene fila en usuarios.
CREATE TABLE IF NOT EXISTS log_seguridad (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER REFERENCES usuarios(id),
  accion TEXT NOT NULL,
  detalle TEXT,
  ip TEXT,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS convocatorias (
  id TEXT PRIMARY KEY,
  fuente TEXT NOT NULL,
  titulo TEXT NOT NULL,
  link TEXT,
  fecha_apertura TEXT,
  fecha_cierre TEXT,
  monto TEXT,
  categoria TEXT,
  descripcion TEXT,
  origen_dato TEXT NOT NULL DEFAULT 'real'
);

CREATE TABLE IF NOT EXISTS postulaciones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  convocatoria_id TEXT NOT NULL REFERENCES convocatorias(id),
  etapa_actual INTEGER NOT NULL DEFAULT 3,
  responsable_id INTEGER REFERENCES usuarios(id),
  fecha_cierre TEXT,
  proximo_hito TEXT,
  proximo_hito_fecha TEXT,
  monto_solicitado INTEGER,
  monto_adjudicado INTEGER,
  resultado TEXT NOT NULL DEFAULT 'en_curso',
  fecha_resultado TEXT,
  escalada_director INTEGER NOT NULL DEFAULT 0,
  resumen_ia TEXT,
  folio TEXT,
  creado_en TEXT NOT NULL DEFAULT (datetime('now')),
  actualizado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS documentos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  postulacion_id INTEGER NOT NULL REFERENCES postulaciones(id),
  tipo TEXT NOT NULL,
  estado TEXT NOT NULL DEFAULT 'pendiente',
  archivo_url TEXT,
  origen TEXT NOT NULL DEFAULT 'externo',
  requiere_firma_externa INTEGER NOT NULL DEFAULT 0,
  estado_firma TEXT NOT NULL DEFAULT 'no_aplica',
  estado_auditoria TEXT NOT NULL DEFAULT 'sin_auditar',
  detalle_auditoria TEXT,
  requisito TEXT,
  sensible INTEGER NOT NULL DEFAULT 0,
  contenido_generado TEXT,
  -- Distingue el checklist de la postulación (Etapa 5) del checklist posterior
  -- para firmar el convenio (Etapa 7, solo aplica si resultado='adjudicada').
  -- Agregado tras revisar el Acta de Evaluación FFOP2026 real (27-jul-2026).
  fase TEXT NOT NULL DEFAULT 'postulacion' CHECK (fase IN ('postulacion', 'convenio')),
  -- Responsable por documento (distinto del responsable de la postulación
  -- completa) — permite repartir un checklist de 15-20 documentos entre
  -- varias personas del equipo en vez de que quede todo bajo una sola.
  responsable_id INTEGER REFERENCES usuarios(id),
  -- Flujo de aprobación con recordatorio automático (inspirado en las
  -- automatizaciones de Monday: "si pasan 48h sin aprobar, recuerda").
  -- generado_en marca desde cuándo un anexo IA espera revisión; se limpia
  -- (vuelve a null) cada vez que se genera un borrador nuevo, para que el
  -- plazo de espera arranque de cero. recordatorio_enviado_en evita mandar
  -- el mismo recordatorio más de una vez por cada borrador generado.
  generado_en TEXT,
  recordatorio_enviado_en TEXT,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Comentarios sobre una postulación o, opcionalmente, sobre un documento
-- puntual dentro de ella (documento_id NULL = comentario general de la
-- postulación). No hay edición/borrado en esta primera versión — es un
-- hilo de conversación simple, append-only, como el log_eventos.
CREATE TABLE IF NOT EXISTS comentarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  postulacion_id INTEGER NOT NULL REFERENCES postulaciones(id),
  documento_id INTEGER REFERENCES documentos(id),
  usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
  texto TEXT NOT NULL,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Cada subida de archivo agrega una fila acá en vez de solo sobreescribir
-- documentos.archivo_url — permite ver versiones anteriores de un mismo
-- documento (ej. el certificado de vigencia vencido vs. el renovado).
CREATE TABLE IF NOT EXISTS documento_versiones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  documento_id INTEGER NOT NULL REFERENCES documentos(id),
  archivo_url TEXT NOT NULL,
  nombre_original TEXT,
  subido_por INTEGER REFERENCES usuarios(id),
  -- Cuando quien sube el archivo es un invitado externo (sin cuenta propia,
  -- ver tabla `invitados`), subido_por queda null y el nombre se guarda acá
  -- como texto, para no perder el rastro de quién lo subió.
  subido_por_invitado TEXT,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Acceso de invitado, acotado a una sola postulación y solo a los documentos
-- que requieren firma externa (ej. el director regional del Serpat en el
-- caso real de FFOP 2026) — para que alguien sin cuenta en el sistema pueda
-- ver qué tiene que firmar y subir la versión firmada, sin exponerle el
-- resto del checklist interno de la fundación. El token en el link es la
-- credencial (mismo patrón que un link "cualquiera con el enlace" de Google
-- Docs) — no hay contraseña ni cuenta que crear.
CREATE TABLE IF NOT EXISTS invitados (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  postulacion_id INTEGER NOT NULL REFERENCES postulaciones(id),
  token TEXT NOT NULL UNIQUE,
  nombre TEXT NOT NULL,
  puede_subir_archivo INTEGER NOT NULL DEFAULT 0,
  creado_por INTEGER REFERENCES usuarios(id),
  expira_en TEXT,
  revocado INTEGER NOT NULL DEFAULT 0,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Plantillas de checklist reutilizables entre postulaciones — evita rearmar
-- desde cero la lista de documentos de cada fondo nuevo. Espejo simplificado
-- de la estructura real de `documentos` (sin los campos que solo aplican a
-- una postulación ya en curso, como estado o archivo).
CREATE TABLE IF NOT EXISTS plantillas_checklist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL,
  descripcion TEXT,
  creado_por INTEGER REFERENCES usuarios(id),
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS plantilla_documentos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plantilla_id INTEGER NOT NULL REFERENCES plantillas_checklist(id),
  tipo TEXT NOT NULL,
  requisito TEXT,
  origen TEXT NOT NULL DEFAULT 'externo',
  requiere_firma_externa INTEGER NOT NULL DEFAULT 0,
  sensible INTEGER NOT NULL DEFAULT 0,
  fase TEXT NOT NULL DEFAULT 'postulacion' CHECK (fase IN ('postulacion', 'convenio')),
  orden INTEGER NOT NULL DEFAULT 0
);

-- Hitos de una postulación — antes solo existía un campo único
-- (postulaciones.proximo_hito / proximo_hito_fecha) que forzaba a elegir
-- "el más importante" y perdía el resto. Ahora puede haber varios (entrega
-- de informe intermedio, rendición de cuentas, firma de convenio, etc.).
-- El campo único de `postulaciones` se mantiene por compatibilidad (lo usa
-- el cálculo del semáforo y las tarjetas del kanban) pero pasa a ser
-- derivado de esta tabla — se recalcula solo, nunca se escribe a mano.
CREATE TABLE IF NOT EXISTS hitos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  postulacion_id INTEGER NOT NULL REFERENCES postulaciones(id),
  titulo TEXT NOT NULL,
  fecha TEXT NOT NULL,
  cumplido INTEGER NOT NULL DEFAULT 0,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Campos personalizados por postulación (línea de financiamiento, si
-- requiere contraparte propia, prioridad estratégica, etc.) — inspirado en
-- los "custom fields" de Asana/Monday: clave→valor de texto libre en vez de
-- migrar una columna nueva cada vez que aparece un dato que solo importa
-- a veces. UNIQUE(postulacion_id, clave) para que agregar la misma clave
-- dos veces actualice el valor en vez de duplicar la fila.
CREATE TABLE IF NOT EXISTS campos_personalizados (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  postulacion_id INTEGER NOT NULL REFERENCES postulaciones(id),
  clave TEXT NOT NULL,
  valor TEXT NOT NULL,
  creado_en TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(postulacion_id, clave)
);

-- Meta de monto adjudicado por año, definida por el director — vincula un
-- número meta a datos reales que ya existen (postulaciones.monto_adjudicado),
-- en vez de un texto suelto (mismo patrón que "Goals" de Asana: se conecta
-- a datos reales y el % se calcula solo, nunca se ingresa a mano).
CREATE TABLE IF NOT EXISTS metas_anuales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  anio INTEGER NOT NULL UNIQUE,
  monto_meta INTEGER NOT NULL,
  actualizado_por INTEGER REFERENCES usuarios(id),
  actualizado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS log_eventos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  postulacion_id INTEGER REFERENCES postulaciones(id),
  usuario_id INTEGER REFERENCES usuarios(id),
  accion TEXT NOT NULL,
  detalle TEXT,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notificaciones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
  postulacion_id INTEGER REFERENCES postulaciones(id),
  tipo TEXT NOT NULL,
  mensaje TEXT NOT NULL,
  leida INTEGER NOT NULL DEFAULT 0,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Matriz de cumplimiento extraída de un PDF de bases (Parte 2 del plan de
-- implementación, "RFP shredding") -- punto 2 de los 5 donde el pipeline
-- llama a Claude (arquitectura-panel-control.md sección 5). Vive separada
-- de `documentos` a propósito: es un borrador que alguien del equipo tiene
-- que revisar y aprobar antes de convertirse en el checklist oficial (nunca
-- se confía ciegamente en la extracción) -- `datos_json` guarda la matriz
-- completa (fechas, montos, topes por categoría, criterios de evaluación,
-- checklist propuesto ya separado en externos vs. anexos propios del fondo,
-- cada dato con su cita textual y página de origen). Al aprobar, genera las
-- filas reales en `documentos` y `hitos` -- ver POST /api/matrices/:id/aprobar.
-- Columnas agregadas el 2026-08-05 (salvaguardas de arquitectura-panel-control.md
-- secciones 4.3/13.3/13.4/14.4): datos_json_original guarda la extracción tal
-- cual salió de la IA, sin ediciones -- nunca se pisa, sirve para contar
-- cuántos campos se editaron antes de aprobar (detector de validación
-- complaciente). requiere_segunda_revision + primera_revision_*/segunda_revision_*
-- implementan la revisión ciega (13.3) sin agregar un estado nuevo a `estado`
-- (para no tener que tocar el CHECK de una tabla que ya puede tener filas
-- reales en producción) -- mientras falte la segunda revisión, `estado` se
-- queda en 'pendiente_revision' aunque ya haya habido una primera aprobación.
CREATE TABLE IF NOT EXISTS matrices_cumplimiento (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  postulacion_id INTEGER NOT NULL REFERENCES postulaciones(id),
  archivo_nombre TEXT,
  estado TEXT NOT NULL DEFAULT 'pendiente_revision' CHECK (estado IN ('pendiente_revision', 'aprobada')),
  datos_json TEXT NOT NULL,
  datos_json_original TEXT,
  editada INTEGER NOT NULL DEFAULT 0,
  modo TEXT NOT NULL,
  prompt_version TEXT,
  tokens_entrada INTEGER,
  tokens_salida INTEGER,
  campos_editados_al_aprobar INTEGER,
  segundos_hasta_revision INTEGER,
  requiere_segunda_revision INTEGER NOT NULL DEFAULT 0,
  motivo_segunda_revision TEXT,
  primera_revision_por INTEGER REFERENCES usuarios(id),
  primera_revision_en TEXT,
  segunda_revision_por INTEGER REFERENCES usuarios(id),
  segunda_revision_en TEXT,
  segunda_revision_decision TEXT,
  segunda_revision_detalle TEXT,
  creado_por INTEGER REFERENCES usuarios(id),
  creado_en TEXT NOT NULL DEFAULT (datetime('now')),
  aprobada_por INTEGER REFERENCES usuarios(id),
  aprobada_en TEXT
);

CREATE TABLE IF NOT EXISTS uso_recursos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tipo TEXT NOT NULL,
  endpoint TEXT,
  postulacion_id INTEGER REFERENCES postulaciones(id),
  tokens_entrada INTEGER,
  tokens_salida INTEGER,
  costo_estimado_usd REAL,
  modo TEXT,
  detalle TEXT,
  creado_en TEXT NOT NULL DEFAULT (datetime('now'))
);
