// Seed con datos reales (convocatorias del monitoreo en producción + caso
// piloto FFOP 2026/Fundación Sewell) y datos sintéticos donde el dato real
// no existe (tracking interno de postulaciones: no es información pública).

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { abrirDb, inicializarSchema, DB_PATH } = require('./db');

const MEMORIA_PATH = path.join(__dirname, '..', '..', 'agente-concursos', 'data', 'memoria.json');

function cargarConvocatoriasReales() {
  if (!fs.existsSync(MEMORIA_PATH)) return {};
  const raw = JSON.parse(fs.readFileSync(MEMORIA_PATH, 'utf8'));
  const porTitulo = {};
  for (const [key, v] of Object.entries(raw)) {
    porTitulo[v.data.titulo] = { key, ...v.data };
  }
  return porTitulo;
}

const TITULOS_ELEGIDOS = [
  'SERVICIO DE ELABORACIÓN DE PLAN DE CULTURA',
  'Escalamiento',
  'RED GTT+ – REGIÓN DE O’HIGGINS – 1° CONVOCATORIA 2026, ETAPA DIAGNÓSTICO',
  'Concurso de Composición Musical Luis Advis 2026',
  'BIENES PÚBLICOS – REGIÓN DE LOS LAGOS – 2° CONVOCATORIA TURISMO NÁUTICO PATAGONIA - COSTA 2026',
  'Concurso de ideas para el Pabellón de Chile en la 20 Bienal de Arquitectura de Venecia 2026',
  'Convocatoria Iberorquestas Juveniles 2026: Galardón Joven Intérprete y Compositor',
  'PAR – REGIÓN DE ATACAMA – 2° CONVOCATORIA INDUSTRIAS CREATIVAS 2026',
];

function main() {
  // Usa el mismo DB_PATH que abrirDb() (respeta PERSIST_DIR si está
  // definida) -- antes este archivo tenía su propia ruta hardcodeada,
  // que se habría desincronizado apenas alguien corriera el seed con
  // PERSIST_DIR configurada (ej. contra el volumen de Railway).
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);

  const db = abrirDb();
  inicializarSchema(db);

  const reales = cargarConvocatoriasReales();
  const disponibles = Object.keys(reales);
  console.log(`Convocatorias reales disponibles en memoria.json: ${disponibles.length}`);

  const insertConv = db.prepare(`INSERT INTO convocatorias
    (id, fuente, titulo, link, fecha_apertura, fecha_cierre, monto, categoria, descripcion, origen_dato)
    VALUES (?,?,?,?,?,?,?,?,?,?)`);

  const convocatoriasUsadas = [];
  for (const titulo of TITULOS_ELEGIDOS) {
    // match flexible por si difieren tildes/mayúsculas menores
    const match = disponibles.find((t) => t.toLowerCase().startsWith(titulo.slice(0, 30).toLowerCase()))
      || disponibles.find((t) => t.toLowerCase().includes(titulo.slice(0, 20).toLowerCase()));
    if (!match) {
      console.warn(`  (no encontrado en memoria.json, se omite): ${titulo}`);
      continue;
    }
    const c = reales[match];
    insertConv.run(c.key, c.fuente, c.titulo, c.link || null, c.fechaApertura || null,
      c.fechaCierre || null, c.monto || null, c.categoria || null, c.descripcion || null, 'real');
    convocatoriasUsadas.push(c);
  }
  console.log(`Convocatorias reales cargadas: ${convocatoriasUsadas.length} de ${TITULOS_ELEGIDOS.length} buscadas`);

  // La convocatoria FFOP 2026 (SERPAT) ya cerró antes de que existiera el
  // monitoreo actual (cerró el 6-mar-2026, el monitoreo parte el 25-jul-2026),
  // así que no está en memoria.json — se agrega a mano con los datos reales
  // del caso piloto (`caso-piloto-FFOP-2026/analisis-caso-real.md`).
  const FFOP_ID = 'SERPAT::ffop-2026-fundacion-sewell';
  insertConv.run(
    FFOP_ID, 'SERPAT',
    'Fondo de Fortalecimiento para Organizaciones Patrimoniales (FFOP) 2026',
    'https://sfgp.gob.cl', '2026-01-23', '2026-03-06', 'Hasta $100.000.000',
    'Patrimonio y memoria',
    'Fondo concursable para organizaciones que administran o gestionan bienes patrimoniales, financia proyectos de gestión, difusión, investigación y puesta en valor del patrimonio cultural.',
    'real'
  );

  // ---- usuarios ----
  // debe_cambiar_password = 1 a propósito: estas son las 5 cuentas reales
  // del primer arranque en producción, así que se tratan igual que un alta
  // hecha por un admin desde el panel de Configuración (Fase D) -- cada
  // persona entra con la clave temporal de abajo, y el propio flujo de login
  // la obliga a poner su clave definitiva y activar 2FA antes de usar el
  // panel. password_actualizada_en queda NULL hasta que eso ocurra, mismo
  // criterio que usa el alta manual (server.js, ruta de creación de usuario).
  const insertUsuario = db.prepare(`INSERT INTO usuarios
    (nombre, email, rol, password_hash, debe_cambiar_password, password_actualizada_en)
    VALUES (?,?,?,?,1,NULL)`);
  const CLAVE_DEMO = 'concursos2026';
  const hash = bcrypt.hashSync(CLAVE_DEMO, 10);
  const idRojas = insertUsuario.run('M. Rojas', 'mrojas@ceodoc.cl', 'equipo', hash).lastInsertRowid;
  const idSoto = insertUsuario.run('J. Soto', 'jsoto@ceodoc.cl', 'equipo', hash).lastInsertRowid;
  const idDiaz = insertUsuario.run('P. Díaz', 'pdiaz@ceodoc.cl', 'equipo', hash).lastInsertRowid;
  const idDirectora = insertUsuario.run('Directora', 'directora@fundacion.cl', 'director', hash).lastInsertRowid;
  const idAdmin = insertUsuario.run('Admin', 'admin@fundacion.cl', 'admin', hash).lastInsertRowid;

  // ---- postulaciones ----
  const insertPost = db.prepare(`INSERT INTO postulaciones
    (convocatoria_id, etapa_actual, responsable_id, fecha_cierre, proximo_hito, proximo_hito_fecha,
     monto_solicitado, monto_adjudicado, resultado, fecha_resultado, escalada_director, resumen_ia, folio)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`);

  function porTitulo(fragmento) {
    return convocatoriasUsadas.find((c) => c.titulo.toLowerCase().includes(fragmento.toLowerCase()));
  }

  const plan = [];

  const c1 = porTitulo('PLAN DE CULTURA');
  if (c1) plan.push({ conv: c1.key, etapa: 6, responsable: idDiaz, hito: 'Cierre de postulación', hitoFecha: c1.fechaCierre, monto: 8500000, escalada: 1,
    resumen: 'Servicio de elaboración de un plan municipal de cultura. Elegible, monto acotado, sin urgencia de escalar más allá del plazo ya vencido.' });

  const c2 = porTitulo('Escalamiento');
  if (c2) plan.push({ conv: c2.key, etapa: 5, responsable: idRojas, hito: 'Cierre de postulación', hitoFecha: c2.fechaCierre, monto: 45000000, escalada: 0,
    resumen: 'Instrumento CORFO de escalamiento productivo, alcance nacional. Cierre muy próximo.' });

  const c3 = porTitulo('RED GTT+');
  if (c3) plan.push({ conv: c3.key, etapa: 5, responsable: idSoto, hito: 'Cierre de postulación', hitoFecha: c3.fechaCierre, monto: 12000000, escalada: 0,
    resumen: 'Etapa de diagnóstico de una red tecnológica regional en O’Higgins.' });

  const c4 = porTitulo('Composición Musical');
  if (c4) plan.push({ conv: c4.key, etapa: 4, responsable: idRojas, hito: 'Fecha límite de consultas', hitoFecha: '2026-07-30', monto: 6000000, escalada: 0,
    resumen: 'Concurso de composición musical, Fondo de la Música. Foco en patrimonio musical chileno.' });

  const c5 = porTitulo('BIENES PÚBLICOS');
  if (c5) plan.push({ conv: c5.key, etapa: 4, responsable: idDiaz, hito: 'Cierre de postulación', hitoFecha: c5.fechaCierre, monto: 30000000, escalada: 0,
    resumen: 'Bienes públicos para turismo náutico patrimonial en la Patagonia, región de Los Lagos.' });

  const c6 = porTitulo('Pabellón de Chile');
  if (c6) plan.push({ conv: c6.key, etapa: 3, responsable: idSoto, hito: 'Cierre de postulación', hitoFecha: c6.fechaCierre, monto: 25000000, escalada: 1,
    resumen: 'Concurso de ideas de arquitectura patrimonial para representar a Chile en la Bienal de Venecia — monto alto, se escaló al director por precedente institucional.' });

  const c7 = porTitulo('Iberorquestas');
  if (c7) plan.push({ conv: c7.key, etapa: 2, responsable: null, hito: null, hitoFecha: null, monto: null, escalada: 0,
    resumen: 'Galardón para jóvenes intérpretes y compositores — recién detectada, todavía sin triage del equipo.' });

  const c8 = porTitulo('INDUSTRIAS CREATIVAS');
  if (c8) plan.push({ conv: c8.key, etapa: 3, responsable: idRojas, hito: 'Cierre de postulación', hitoFecha: c8.fechaCierre, monto: 40000000, escalada: 0,
    resumen: 'Segunda convocatoria de industrias creativas en Atacama, plazo amplio todavía.' });

  const postIds = {};
  for (const p of plan) {
    const r = insertPost.run(p.conv, p.etapa, p.responsable, p.hitoFecha, p.hito, p.hitoFecha,
      p.monto, null, 'en_curso', null, p.escalada, p.resumen, null);
    postIds[p.conv] = r.lastInsertRowid;
  }

  // FFOP 2026 — caso real, ya resuelto
  const ffopId = insertPost.run(
    FFOP_ID, 7, idRojas, '2026-03-06', 'Resultado publicado', '2026-06-26',
    100000000, 96000000, 'adjudicada', '2026-06-26', 1,
    'Fondo de Fortalecimiento para Organizaciones Patrimoniales — Fundación Sewell postuló la restauración y puesta en valor de espacios patrimoniales de la ex ciudad minera. Seleccionada con nota 77,5/100, rebajada de $100.000.000 a $96.000.000 por observaciones de documentación.',
    '143145'
  ).lastInsertRowid;
  postIds[FFOP_ID] = ffopId;

  // ---- hitos ----
  // `postulaciones.proximo_hito`/`proximo_hito_fecha` (arriba) ya no se
  // escriben a mano en producción — se recalculan solos desde esta tabla
  // (`recalcularProximoHito()` en server.js). Acá en el seed sí se escriben
  // los dos en paralelo, a propósito, para que ambos queden consistentes
  // desde el primer arranque.
  const insertHito = db.prepare(`INSERT INTO hitos (postulacion_id, titulo, fecha, cumplido) VALUES (?,?,?,?)`);
  for (const p of plan) {
    if (p.hito && p.hitoFecha) insertHito.run(postIds[p.conv], p.hito, p.hitoFecha, 0);
  }
  // FFOP 2026 tiene más historia real que un solo hito — se agregan los que
  // ya pasaron (cumplidos) y los que siguen pendientes tras la adjudicación,
  // para que el calendario y el cronograma de la postulación no muestren
  // solo una fecha suelta.
  insertHito.run(ffopId, 'Cierre de postulación', '2026-03-06', 1);
  insertHito.run(ffopId, 'Resultado publicado', '2026-06-26', 1);
  insertHito.run(ffopId, 'Firma de convenio con SERPAT', '2026-08-15', 0);
  insertHito.run(ffopId, 'Primera rendición de cuentas', '2026-11-30', 0);

  // Recalcula proximo_hito/proximo_hito_fecha desde la tabla `hitos` para
  // todas las postulaciones (mismo criterio que `recalcularProximoHito()`
  // en server.js) — así el seed nunca deja los dos lados desincronizados,
  // ni siquiera para FFOP, que ya tiene hitos cumplidos y pendientes mezclados.
  const proximoPorPostulacion = db.prepare(`
    SELECT titulo, fecha FROM hitos WHERE postulacion_id = ? AND cumplido = 0
    ORDER BY fecha ASC LIMIT 1`);
  const actualizarProximo = db.prepare(`UPDATE postulaciones SET proximo_hito = ?, proximo_hito_fecha = ? WHERE id = ?`);
  for (const id of Object.values(postIds)) {
    const proximo = proximoPorPostulacion.get(id);
    actualizarProximo.run(proximo ? proximo.titulo : null, proximo ? proximo.fecha : null, id);
  }

  // ---- documentos ----
  const insertDoc = db.prepare(`INSERT INTO documentos
    (postulacion_id, tipo, estado, origen, requiere_firma_externa, estado_firma, estado_auditoria, detalle_auditoria, requisito, sensible)
    VALUES (?,?,?,?,?,?,?,?,?,?)`);

  function docsGenericos(postId, variante) {
    const base = [
      ['Certificado de vigencia', 'reunido', 'externo', 0, 'no_aplica', 'cumple', 'Vigente, emitido dentro de los últimos 6 meses.', 'Certificado de vigencia con antigüedad menor a 6 meses.', 0],
      ['RUT de la organización', 'reunido', 'externo', 0, 'no_aplica', 'cumple', 'Coincide con el nombre de la organización postulante.', 'RUT vigente de la persona jurídica.', 0],
      ['Cotización / presupuesto detallado', 'reunido', 'externo', 0, 'no_aplica', 'cumple', 'Presupuesto detallado por ítem, dentro de los topes de la convocatoria.', 'Presupuesto detallado y fundamentado por ítem de gasto.', 0],
      ['Formulario de postulación (Anexo N°1)', 'pendiente', 'generado_ia', 0, 'no_aplica', 'sin_auditar', null, 'Formulario oficial de postulación, completo y firmado por el representante legal.', 0],
    ];
    if (variante === 'rojo') {
      base[0][1] = 'vencido'; base[0][5] = 'no_cumple';
      base[0][6] = 'El certificado adjunto tiene más de 6 meses de antigüedad — hay que solicitar uno nuevo.';
    }
    if (variante === 'sin_datos') return []; // convocatoria recién detectada, sin checklist todavía (no hay matriz aprobada)
    return base;
  }

  for (const p of plan) {
    const postId = postIds[p.conv];
    let variante = 'ok';
    if (p.conv === c1.key) variante = 'rojo';
    if (c7 && p.conv === c7.key) variante = 'sin_datos';
    for (const d of docsGenericos(postId, variante)) {
      insertDoc.run(postId, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8]);
    }
  }

  // FFOP 2026 — checklist real del caso piloto
  const docsFFOP = [
    ['RUT de la organización', 'reunido', 'externo', 0, 'no_aplica', 'cumple',
      'RUT vigente adjunto, sin observaciones en el acta de evaluación.',
      'Fotocopia simple del Rol Único Tributario de la persona jurídica, por ambos lados.', 0],
    ['Cédula del representante legal', 'reunido', 'externo', 0, 'no_aplica', 'cumple', 'Cédula vigente adjunta.',
      'Cédula de identidad vigente del representante legal.', 0],
    ['Facultades de representación legal', 'reunido', 'externo', 0, 'no_aplica', 'cumple',
      'Poder/mandato de representación legal vigente, dentro de los 6 meses de antigüedad que exigen las bases.',
      'Documentación que acredite facultades de representación legal vigente, con antigüedad no superior a 6 meses — distinto de la cédula de identidad.', 0],
    ['Certificado de vigencia', 'reunido', 'externo', 0, 'no_aplica', 'cumple',
      'Emitido 12-ene-2026 — dentro de los 6 meses que exigen las bases.',
      'Certificado de vigencia con antigüedad menor a 6 meses.', 0],
    ['Escritura pública o acta de constitución', 'reunido', 'externo', 0, 'no_aplica', 'cumple',
      'Escritura de constitución completa — coincide con fecha, fundadores y estatutos declarados.',
      'Copia de la escritura pública o acta de constitución, con fecha, fundadores, primer directorio y aprobación de estatutos.', 0],
    ['Estatutos de la organización', 'reunido', 'externo', 0, 'no_aplica', 'cumple', 'Estatutos completos y legibles.',
      'Estatutos vigentes de la persona jurídica sin fines de lucro.', 0],
    ['Certificado de directorio', 'reunido', 'externo', 0, 'no_aplica', 'cumple', 'Nómina de directorio vigente adjunta.',
      'Certificado de directorio vigente.', 0],
    ['Ficha de la institución (Registro Central de Colaboradores del Estado)', 'reunido', 'externo', 0, 'no_aplica', 'cumple',
      'Se verificó que el documento adjunto es la "ficha de la institución" completa emitida por registros19862.cl, no el "certificado de inscripción" — las bases advierten explícitamente que no son equivalentes.',
      '"Ficha de la institución" del Registro Central de Colaboradores del Estado (Ley 19.862), no equivalente al certificado de inscripción.', 0],
    ['Dosier de la organización', 'reunido', 'externo', 0, 'no_aplica', 'cumple',
      'Dosier completo con historia, objetivos, quehacer, organigrama y apoyo gráfico hasta diciembre de 2025.',
      'Dosier con historia, objetivos, quehacer, organigrama y apoyo gráfico de la organización.', 0],
    ['Informe de buenas prácticas organizacionales', 'reunido', 'externo', 0, 'no_aplica', 'cumple',
      'Aborda de forma concreta y verificable los 5 ámbitos exactos que cita el Acta de Evaluación: equidad y diversidad de género; inclusión de personas con discapacidad; derechos humanos y memoria; jóvenes e infancia; y buen ambiente y condiciones laborales — coincide con los 100/100 puntos reales en este criterio (25% de la nota final).',
      'Informe de buenas prácticas organizacionales con evidencia verificable — Criterio 1 de evaluación, 25% de la nota.', 0],
    ['Contrato de prestación de servicios — Rodrigo Orellana (prevencionista)', 'reunido', 'externo', 0, 'no_aplica', 'no_cumple',
      'El documento reunido es un contrato de 2023, ya vencido. Las bases piden "contrato de prestación de servicios vigente" — falta la versión actual. (Este fue el error real que le costó $4.000.000 a Fundación Sewell.)',
      'Personal a honorario: contrato de prestación de servicios vigente.', 1],
    ['Declaración F29 — Rodrigo Orellana', 'pendiente', 'externo', 0, 'no_aplica', 'falta',
      'No se ha subido ningún archivo para este requisito. (Este fue el segundo error real del caso: faltó también la última declaración F29.)',
      'Personal a honorario: última declaración mensual (F29).', 1],
    ['Anexo N°1 — Certificado dirección regional Serpat', 'pendiente', 'generado_ia', 1, 'pendiente', 'sin_auditar',
      'Borrador generado y aprobado por el equipo — falta la firma del director regional del Serpat antes de contar como "reunido".',
      'Certificado de líneas de trabajo con Serpat, firmado por el director regional.', 0],
    ['Anexo N°2 — Carta de compromiso (personal nuevo)', 'reunido', 'generado_ia', 0, 'no_aplica', 'cumple',
      'Generado con los datos del CV cargado y aprobado por M. Rojas.',
      'Carta de compromiso firmada por cada persona nueva a contratar.', 0],
    ['Anexo N°3 — Programación de actividades', 'pendiente', 'generado_ia', 0, 'no_aplica', 'sin_auditar',
      '6 actividades completadas automáticamente desde el cronograma de la Etapa 4 — pendiente de revisión antes de aprobar.',
      'Tabla de actividades con período de ejecución y fuente de financiamiento.', 0],

    // Etapa 7 — postulación ya adjudicada (folio 143145). Las bases (secciones 7.1 a 7.4)
    // exigen un segundo checklist, distinto al de la postulación, para firmar el convenio.
    // Detectado al revisar el Acta de Evaluación FFOP2026: nuestro checklist se quedaba
    // en los documentos de postulación y no modelaba nada de esta etapa posterior.
    ['Convenio — Certificado de la Inspección del Trabajo', 'pendiente', 'externo', 0, 'no_aplica', 'falta',
      'No se ha subido ningún archivo. Las bases (7.3) exigen certificado sin deudas previsionales de los últimos 2 años, como requisito para firmar el convenio.',
      'Certificado de la Inspección del Trabajo, sin deudas previsionales de los últimos 2 años.', 0],
    ['Convenio — Declaración jurada simple sobre rendiciones', 'pendiente', 'externo', 0, 'no_aplica', 'falta',
      'No se ha subido ningún archivo. Declara el estado de rendiciones de convenios vigentes con el Serpat/Mincap.',
      'Declaración jurada simple sobre el estado de rendiciones de convenios vigentes con el Serpat.', 0],
    ['Convenio — Garantía por el monto adjudicado', 'pendiente', 'externo', 0, 'no_aplica', 'falta',
      'No se ha subido ningún archivo. Las bases piden una de 6 instrumentos (letra de cambio, pagaré, boleta de garantía, póliza, vale vista o certificado de fianza) por el 100% de los $96.000.000 adjudicados.',
      'Garantía por el 100% del monto adjudicado (letra de cambio, pagaré, boleta de garantía, póliza de seguro, vale vista o certificado de fianza).', 1],
    ['Convenio — Ficha de la institución actualizada (Oficio Circular N°21/2025)', 'pendiente', 'externo', 0, 'no_aplica', 'falta',
      'No se ha subido ningún archivo. Es una ficha distinta de la presentada en la postulación: debe estar actualizada según el Oficio Circular N°21/2025 del Ministerio de Hacienda.',
      'Ficha de la institución actualizada conforme al Oficio Circular N°21/2025 (Ministerio de Hacienda), exigida para la firma del convenio.', 0],
    ['Convenio — Renuncia a otro financiamiento (si aplica)', 'pendiente', 'externo', 0, 'no_aplica', 'sin_auditar',
      'Condicional: solo aplica si la organización recibe financiamiento de otro fondo del Serpat/Mincap para los mismos gastos. Falta confirmar con la organización si corresponde presentarlo.',
      'Carta de renuncia a otro fondo, o declaración jurada notarial optando por el FFOP, si corresponde.', 0],
  ];
  for (const d of docsFFOP) {
    insertDoc.run(ffopId, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8]);
  }
  // Los 5 documentos de convenio se cargaron con el prefijo "Convenio — " en el
  // tipo (ver docsFFOP arriba); acá quedan marcados también en su propio campo
  // estructurado `fase`, para que la UI los agrupe sin depender de parsear texto.
  db.prepare(`UPDATE documentos SET fase = 'convenio' WHERE postulacion_id = ? AND tipo LIKE 'Convenio — %'`).run(ffopId);

  // ---- invitados externos (demo) ----
  // El Anexo N°1 de FFOP requiere la firma del director regional del Serpat
  // (caso real) — se deja un acceso externo de ejemplo, ya usable, para no
  // depender de que alguien lo cree a mano antes de poder probar la función.
  const insertInvitado = db.prepare(`INSERT INTO invitados (postulacion_id, token, nombre, puede_subir_archivo, creado_por) VALUES (?,?,?,?,?)`);
  insertInvitado.run(ffopId, crypto.randomBytes(20).toString('hex'), 'Director regional Serpat', 1, idRojas);

  // ---- campos personalizados (demo) ----
  const insertCampo = db.prepare(`INSERT INTO campos_personalizados (postulacion_id, clave, valor) VALUES (?,?,?)`);
  insertCampo.run(ffopId, 'Línea de financiamiento', 'Patrimonio y memoria');
  insertCampo.run(ffopId, 'Requiere contraparte propia', 'No');
  if (c6) insertCampo.run(postIds[c6.key], 'Prioridad estratégica', 'Alta — precedente institucional');

  // ---- log_eventos ----
  const insertLog = db.prepare(`INSERT INTO log_eventos (postulacion_id, usuario_id, accion, detalle) VALUES (?,?,?,?)`);
  insertLog.run(ffopId, idRojas, 'matriz_aprobada', 'Matriz de cumplimiento de Bases_FFOP_2026.pdf aprobada sin ediciones.');
  insertLog.run(ffopId, idRojas, 'anexo_aprobado', 'Anexo N°2 — Carta de compromiso, aprobado tras revisión.');
  insertLog.run(ffopId, idRojas, 'documento_auditado', 'Contrato de prestación de servicios (Rodrigo Orellana) marcado no_cumple por la auditoría IA.');
  insertLog.run(ffopId, idDirectora, 'resultado_registrado', 'Folio 143145 — adjudicada, $96.000.000 (rebajado de $100.000.000).');
  if (c1) insertLog.run(postIds[c1.key], idDiaz, 'postulacion_creada', 'Postulación creada a partir de la convocatoria detectada en Mercado Público.');

  // ---- notificaciones ----
  const insertNotif = db.prepare(`INSERT INTO notificaciones (usuario_id, postulacion_id, tipo, mensaje, leida) VALUES (?,?,?,?,?)`);
  if (c7) insertNotif.run(idRojas, postIds[c7.key], 'nueva_convocatoria', `Nueva convocatoria detectada: ${c7.titulo}`, 0);
  if (c6) insertNotif.run(idSoto, postIds[c6.key], 'escalada_triage', `Convocatoria escalada a la directora: ${c6.titulo}`, 0);
  insertNotif.run(idRojas, ffopId, 'documento_por_vencer', 'FFOP 2026: falta la firma externa del Anexo N°1.', 0);
  insertNotif.run(idRojas, ffopId, 'resultado_publicado', 'FFOP 2026: resultado publicado — adjudicada.', 1);
  if (c1) insertNotif.run(idDiaz, postIds[c1.key], 'documento_por_vencer', 'Certificado de vigencia vencido — hay que renovarlo antes de enviar.', 0);

  // ---- uso_recursos (costos, sección 7) ----
  const insertUso = db.prepare(`INSERT INTO uso_recursos (tipo, endpoint, postulacion_id, tokens_entrada, tokens_salida, costo_estimado_usd, modo, detalle) VALUES (?,?,?,?,?,?,?,?)`);
  insertUso.run('llamada_ia', '/api/ia/analizar-bases', ffopId, 8200, 1400, 0.31, 'sintetico', 'Extracción de matriz — Bases_FFOP_2026.pdf (seed, sin llamada real).');
  insertUso.run('llamada_ia', '/api/ia/generar-anexos', ffopId, 2100, 900, 0.09, 'sintetico', 'Generación de 3 anexos (seed, sin llamada real).');
  insertUso.run('llamada_ia', '/api/ia/auditar-documentos', ffopId, 3400, 600, 0.12, 'sintetico', 'Auditoría de 9 documentos (seed, sin llamada real).');

  // ---- meta anual (demo) ----
  // Año actual, no un valor fijo — así el seed sigue siendo coherente
  // corriéndolo en cualquier fecha futura, no solo hoy.
  const insertMeta = db.prepare(`INSERT INTO metas_anuales (anio, monto_meta, actualizado_por) VALUES (?,?,?)`);
  insertMeta.run(new Date().getFullYear(), 180000000, idDirectora);

  console.log('Seed completo.');
  console.log(`Usuarios reales, clave TEMPORAL para todos (deben cambiarla + activar 2FA en el primer ingreso): "${CLAVE_DEMO}"`);
  console.log('  Equipo:    mrojas@ceodoc.cl / jsoto@ceodoc.cl / pdiaz@ceodoc.cl');
  console.log('  Director:  directora@fundacion.cl');
  console.log('  Admin:     admin@fundacion.cl');
  db.close();
}

main();
