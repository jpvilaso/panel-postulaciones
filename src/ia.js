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

module.exports = { auditarDocumento, generarAnexo, tieneApiKeyReal };
