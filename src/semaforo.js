// Cálculo del semáforo — arquitectura-panel-control.md, sección 4.
// Nunca se guarda a mano: se deriva siempre de datos que ya existen
// (cronograma + estado de los documentos), acá y en el resto de la app.

const N_DIAS_AMBAR = 5; // parámetro configurable (sección 4) — fijo acá para el demo

function diasHasta(fechaISO) {
  if (!fechaISO) return null;
  const hoy = new Date();
  hoy.setHours(0, 0, 0, 0);
  const destino = new Date(fechaISO + 'T00:00:00');
  return Math.round((destino - hoy) / (1000 * 60 * 60 * 24));
}

function calcularSemaforo(postulacion, documentos) {
  if (postulacion.resultado === 'adjudicada' || postulacion.resultado === 'rechazada') {
    return { color: 'verde', razon: 'Postulación cerrada (resultado ya conocido).' };
  }

  const docsObligatorios = documentos.filter((d) => !d.opcional);
  const vencidoOfaltaCumplir = docsObligatorios.find(
    (d) => d.estado === 'vencido' || d.estado_auditoria === 'no_cumple'
  );
  if (vencidoOfaltaCumplir) {
    return {
      color: 'rojo',
      razon: `Documento "${vencidoOfaltaCumplir.tipo}" ${
        vencidoOfaltaCumplir.estado === 'vencido' ? 'vencido' : 'no cumple el requisito (auditoría IA)'
      }.`,
    };
  }

  const diasHito = diasHasta(postulacion.proximo_hito_fecha);
  const diasCierre = diasHasta(postulacion.fecha_cierre);

  if ((diasHito !== null && diasHito < 0) || (diasCierre !== null && diasCierre < 0)) {
    return { color: 'rojo', razon: 'Un hito o la fecha de cierre ya pasó sin completarse.' };
  }

  const faltaDoc = docsObligatorios.find((d) => d.estado === 'pendiente');
  if (diasHito !== null && diasHito <= N_DIAS_AMBAR) {
    return { color: 'ambar', razon: `El próximo hito vence en ${diasHito} día(s).` };
  }
  if (faltaDoc && diasCierre !== null && diasCierre <= N_DIAS_AMBAR) {
    return { color: 'ambar', razon: `Falta reunir "${faltaDoc.tipo}" y el cierre está cerca.` };
  }

  return { color: 'verde', razon: 'En plazo, sin documentos vencidos.' };
}

function porcentajeAvance(documentos) {
  const obligatorios = documentos.filter((d) => !d.opcional);
  if (obligatorios.length === 0) return 0;
  const reunidos = obligatorios.filter((d) => d.estado === 'reunido').length;
  return Math.round((reunidos / obligatorios.length) * 100);
}

module.exports = { calcularSemaforo, porcentajeAvance, diasHasta, N_DIAS_AMBAR };
