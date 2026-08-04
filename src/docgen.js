// Genera un .docx real y descargable a partir del borrador de texto que
// devuelve /api/documentos/:id/generar-anexo — para que el equipo pueda
// bajarlo, editarlo o hacerlo firmar fuera del sistema, y subir la versión
// final (src/server.js, rutas /descargar-borrador y /subir-archivo).

const { Document, Packer, Paragraph, TextRun, HeadingLevel } = require('docx');

async function borradorADocx({ titulo, subtitulo, cuerpo }) {
  const parrafos = cuerpo
    .split(/\n+/)
    .filter((l) => l.trim().length > 0)
    .map((linea) => new Paragraph({ children: [new TextRun(linea)], spacing: { after: 200 } }));

  const doc = new Document({
    sections: [
      {
        children: [
          new Paragraph({ text: titulo, heading: HeadingLevel.HEADING_1 }),
          new Paragraph({ children: [new TextRun({ text: subtitulo, italics: true, color: '6B7280' })], spacing: { after: 300 } }),
          ...parrafos,
          new Paragraph({ children: [new TextRun({ text: '— Borrador generado por el Agente de Concursos. Revisar antes de aprobar o enviar a firma.', italics: true, size: 18, color: '9CA3AF' })], spacing: { before: 400 } }),
        ],
      },
    ],
  });

  return Packer.toBuffer(doc);
}

module.exports = { borradorADocx };
