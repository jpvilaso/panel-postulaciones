// Los 5 puntos donde el pipeline llama a Claude (arquitectura-panel-control.md,
// sección 5). Si hay ANTHROPIC_API_KEY configurada, llama de verdad a la API;
// si no, cae a un resultado sintético — determinístico y basado en los datos
// reales que ya existen, nunca inventado al azar — para que la demo funcione
// sin credenciales. El modo usado queda siempre marcado en la respuesta.

let Anthropic = null;
try {
  // Carga perezosa: si el paquete no está instalado o no hay API key, no falla.
  Anthropic = require('@anthropic-ai/sdk');
} catch (e) {
  Anthropic = null;
}

function tieneApiKeyReal() {
  return Boolean(process.env.ANTHROPIC_API_KEY) && Anthropic;
}

function cliente() {
  return new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
}

async function llamarClaude(system, prompt, maxTokens = 700) {
  const client = cliente();
  const modelo = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5-20250929';
  const resp = await client.messages.create({
    model: modelo,
    max_tokens: maxTokens,
    system,
    messages: [{ role: 'user', content: prompt }],
  });
  const texto = resp.content.map((b) => (b.type === 'text' ? b.text : '')).join('\n').trim();
  return {
    texto,
    tokensEntrada: resp.usage ? resp.usage.input_tokens : null,
    tokensSalida: resp.usage ? resp.usage.output_tokens : null,
  };
}

// ---- Punto 5: Auditoría de documentos ----
async function auditarDocumento({ documento, postulacion, convocatoria }) {
  if (tieneApiKeyReal() && documento.archivo_texto) {
    const system = 'Eres un auditor de postulaciones a fondos concursables chilenos. Lees un documento y decides si cumple exactamente el requisito indicado. Nunca inventes contenido que no esté en el documento. Responde en JSON: {"estado": "cumple"|"no_cumple"|"falta", "detalle": "razón breve citando el documento"}.';
    const prompt = `Requisito exacto: "${documento.requisito}"\n\nDocumento reunido (texto completo):\n${documento.archivo_texto}\n\n¿Cumple el requisito? Responde solo el JSON.`;
    try {
      const { texto, tokensEntrada, tokensSalida } = await llamarClaude(system, prompt, 400);
      const json = JSON.parse(texto.match(/\{[\s\S]*\}/)[0]);
      return { estado: json.estado, detalle: json.detalle, modo: 'real', tokensEntrada, tokensSalida };
    } catch (e) {
      // si la llamada real falla, no se inventa un resultado — se marca explícito
      return { estado: 'sin_auditar', detalle: `No se pudo completar la auditoría automática (${e.message}). Revisar a mano.`, modo: 'error' };
    }
  }

  // Modo demo (sin API key o sin texto de archivo): heurística determinística
  // sobre el estado ya declarado, nunca al azar.
  if (documento.estado === 'vencido') {
    return {
      estado: 'no_cumple',
      detalle: `Modo demo (sin ANTHROPIC_API_KEY): el documento está marcado "vencido" — no cumple el requisito "${documento.requisito || documento.tipo}".`,
      modo: 'sintetico',
    };
  }
  if (documento.estado !== 'reunido') {
    return {
      estado: 'falta',
      detalle: `Modo demo (sin ANTHROPIC_API_KEY): no hay ningún archivo reunido todavía para "${documento.tipo}".`,
      modo: 'sintetico',
    };
  }
  return {
    estado: 'cumple',
    detalle: `Modo demo (sin ANTHROPIC_API_KEY): el documento está reunido y no hay ninguna señal de que no cumpla "${documento.requisito || documento.tipo}". Con una API key real, la IA leería el contenido completo en vez de esta heurística.`,
    modo: 'sintetico',
  };
}

// ---- Punto 3: Generación de anexos ----
async function generarAnexo({ documento, postulacion, convocatoria }) {
  const datosReales = `Convocatoria: ${convocatoria.titulo} (${convocatoria.fuente}). Monto solicitado: ${postulacion.monto_solicitado ? '$' + postulacion.monto_solicitado.toLocaleString('es-CL') : 'no definido'}. Responsable: ${postulacion.responsable_nombre || 'sin asignar'}.`;

  if (tieneApiKeyReal()) {
    const system = 'Eres un asistente que llena formularios/anexos reales de fondos concursables chilenos con datos que ya existen en la postulación. Nunca inventes montos, fechas ni nombres que no te den. Si falta un dato, dilo explícitamente en vez de inventarlo.';
    const prompt = `Anexo a redactar: "${documento.tipo}".\nDatos reales disponibles:\n${datosReales}\n\nRedacta un borrador breve (4-6 líneas) del contenido de este anexo usando solo estos datos.`;
    try {
      const { texto, tokensEntrada, tokensSalida } = await llamarClaude(system, prompt, 500);
      return { borrador: texto, modo: 'real', tokensEntrada, tokensSalida };
    } catch (e) {
      return { borrador: `No se pudo generar el borrador automático (${e.message}). Redactar a mano.`, modo: 'error' };
    }
  }

  return {
    borrador: `Modo demo (sin ANTHROPIC_API_KEY) — borrador generado con una plantilla simple, no con IA real:\n\n` +
      `Anexo "${documento.tipo}" para la convocatoria "${convocatoria.titulo}" (${convocatoria.fuente}). ${datosReales} ` +
      `Este texto se arma solo con datos que ya existen en el sistema — con una API key real, Claude redactaría los campos narrativos con más detalle.`,
    modo: 'sintetico',
  };
}

// ---- Punto 2: Extracción de requisitos / matriz de cumplimiento ----
// Es el endpoint de mayor valor de los 5 (plan-implementacion.md, Parte 2):
// analiza el PDF completo de las bases (sin RAG -- un solo documento entero
// en el contexto, decisión ya tomada en el backlog) y devuelve una matriz
// estructurada, no un resumen libre -- cada dato con su cita textual, para
// que un humano la pueda verificar en vez de confiar ciegamente. El caso
// real que motiva esto: a Fundación Sewell le costó $4.000.000 que "personal
// a honorario" tuviera requisitos de documentación DISTINTOS al resto (un
// contrato vigente + la última F29), algo que un checklist genérico no
// habría capturado -- por eso el prompt pide explícitamente requisitos
// "por tipo de gasto/categoría", no una lista plana.
//
// PROMPT_VERSION_MATRIZ (arquitectura-panel-control.md 14.4, "versionado de
// prompts"): sube cada vez que cambie el texto de PROMPT_SISTEMA_MATRIZ.
// Se guarda junto con cada matriz extraída (matrices_cumplimiento.prompt_version)
// y en uso_recursos.detalle -- sin esto no hay forma de auditar después por
// qué una extracción vieja salió distinta de una nueva, ni de revertir un
// cambio de prompt que resultó peor que el anterior.
const PROMPT_VERSION_MATRIZ = 'matriz-v1-2026-08-05';
const PROMPT_SISTEMA_MATRIZ = `Eres un analista experto en bases de fondos concursables chilenos (RFP shredding). Lees un documento de bases completo y extraes una matriz de cumplimiento estructurada, nunca un resumen libre.

Reglas estrictas:
- Cada dato que extraigas debe venir acompañado de una cita textual breve (la frase exacta del documento de donde sale) y, si puedes identificarla, la sección o página de origen.
- Nunca inventes un requisito, monto o fecha que no esté explícito en el texto. Si un campo no aparece en el documento, usa null.
- Presta atención especial a requisitos que varíen "por tipo de gasto" o categoría (ej. personal a honorario, bienes, servicios de terceros) -- las bases suelen exigir documentación distinta según la categoría, y ese es el error más costoso si se pasa por alto.
- Separa el checklist de documentos en dos grupos: "externo" (la organización debe reunirlo o solicitarlo -- certificados, contratos, cotizaciones) y "generado_ia" (un anexo o formulario propio del fondo que se llena con datos que ya existen en el sistema, ej. "Anexo N°1", "Anexo N°2").
- Responde SOLO con el JSON, sin texto antes ni después, seguiendo exactamente este esquema:

{
  "fecha_cierre": "YYYY-MM-DD o null",
  "monto_maximo": <número en CLP o null>,
  "resumen": "1-2 líneas de qué es el fondo",
  "topes_gasto_por_categoria": [ { "categoria": "...", "tope": "texto o número o null", "cita": "..." } ],
  "checklist": [ { "tipo": "...", "origen": "externo|generado_ia", "aplica_a": "categoría o null si es general", "requisito": "texto exacto del requisito", "cita": "...", "pagina": <número o null> } ],
  "criterios_evaluacion": [ { "criterio": "...", "ponderacion": "texto o null", "cita": "..." } ]
}`;

async function analizarBases({ textoPdf, nombreArchivo }) {
  if (tieneApiKeyReal()) {
    try {
      const { texto, tokensEntrada, tokensSalida } = await llamarClaude(
        PROMPT_SISTEMA_MATRIZ,
        `Documento de bases (texto completo, extraído de "${nombreArchivo}"):\n\n${textoPdf}`,
        6000
      );
      const match = texto.match(/\{[\s\S]*\}/);
      if (!match) throw new Error('La respuesta no contenía JSON.');
      const matriz = JSON.parse(match[0]);
      return { matriz, modo: 'real', tokensEntrada, tokensSalida, promptVersion: PROMPT_VERSION_MATRIZ };
    } catch (e) {
      return {
        matriz: null,
        modo: 'error',
        error: `No se pudo completar la extracción automática (${e.message}). Revisar las bases a mano.`,
        promptVersion: PROMPT_VERSION_MATRIZ,
      };
    }
  }

  // Modo demo (sin ANTHROPIC_API_KEY): heurística determinística sobre el
  // texto real del PDF -- busca frases de obligación ("debe", "deberá", "es
  // requisito") cerca de palabras de tipos de documento conocidos, y arma un
  // checklist a partir de eso. No inventa nada que no esté en el texto, pero
  // es mucho más burdo que la extracción real -- no reemplaza tener una API
  // key real para dar por validada esta funcionalidad.
  const TIPOS_CONOCIDOS = [
    ['certificado de vigencia', 'Certificado de vigencia'],
    ['rut', 'RUT de la organización'],
    ['contrato de prestación de servicios', 'Contrato de prestación de servicios'],
    ['f29', 'Declaración F29'],
    ['declaración jurada', 'Declaración jurada'],
    ['garantía', 'Garantía'],
    ['estatutos', 'Estatutos de la organización'],
    ['cédula de identidad', 'Cédula de identidad del representante legal'],
    ['escritura', 'Escritura pública o acta de constitución'],
    ['presupuesto', 'Presupuesto detallado'],
  ];
  const textoLower = textoPdf.toLowerCase();
  const oraciones = textoPdf.split(/(?<=[.;])\s+/);
  const checklist = [];
  for (const [clave, tipo] of TIPOS_CONOCIDOS) {
    const oracion = oraciones.find((o) => o.toLowerCase().includes(clave));
    if (oracion) {
      checklist.push({
        tipo,
        origen: 'externo',
        aplica_a: null,
        requisito: oracion.trim().slice(0, 300),
        cita: oracion.trim().slice(0, 300),
        pagina: null,
      });
    }
  }
  const fechaMatch = textoPdf.match(/(\d{1,2}\s+de\s+\w+\s+de\s+20\d{2}|\d{1,2}[\/-]\d{1,2}[\/-]20\d{2})/i);
  return {
    matriz: {
      fecha_cierre: null,
      monto_maximo: null,
      resumen: `Modo demo (sin ANTHROPIC_API_KEY): checklist armado con una búsqueda de palabras clave sobre "${nombreArchivo}", no con lectura real del documento. Con una API key real, Claude extraería la matriz completa (fechas, montos, topes por categoría, criterios de evaluación) con citas.`,
      topes_gasto_por_categoria: [],
      checklist,
      criterios_evaluacion: [],
      _fechaDetectadaEnTexto: fechaMatch ? fechaMatch[0] : null,
    },
    modo: 'sintetico',
    promptVersion: PROMPT_VERSION_MATRIZ,
  };
}

// Tope de tamaño del PDF de bases (arquitectura-panel-control.md 13.2): si
// el texto extraído excede esto, `server.js` ni siquiera llama a esta
// función -- no truncar ni fragmentar el documento (perder un requisito por
// no leerlo completo fue justo el error real de Fundación Sewell). Medido en
// caracteres del texto ya extraído por pdf-parse, no en tamaño del archivo
// PDF (un PDF con imágenes pesa mucho pero puede tener poco texto real, y
// viceversa) -- ~180.000 caracteres son unas 60-70 páginas de bases típicas,
// bastante por encima del caso real de FFOP 2026 (86.000 caracteres, 31 páginas).
const MAX_CARACTERES_BASES = 180000;

module.exports = { auditarDocumento, generarAnexo, analizarBases, tieneApiKeyReal, MAX_CARACTERES_BASES, PROMPT_VERSION_MATRIZ };
