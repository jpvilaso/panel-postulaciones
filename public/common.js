// Utilidades compartidas por todas las páginas: fetch con manejo de sesión,
// y la barra de navegación persistente (arquitectura-panel-control.md, 3.1).

// Encadena el "?volver=" a través de login/cambiar-password/configurar-2fa
// (server.js, conVolver()) -- si la URL actual trae uno, se usa ESE en vez
// del destino normal según el rol. Server.js ya se encarga de que "volver"
// apunte de nuevo a la URL protegida original en cada paso intermedio, así
// que acá basta con leerlo tal cual y no hace falta re-encadenarlo: cuando
// ya no falte ningún paso, "volver" va a apuntar derecho a /sso/agente-concursos
// (u otra ruta protegida), que resuelve el resto solo.
function destinoFinal(destinoNormal) {
  const params = new URLSearchParams(window.location.search);
  const volver = params.get('volver');
  return volver ? decodeURIComponent(volver) : destinoNormal;
}

async function api(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (res.status === 401) {
    window.location.href = '/login.html';
    throw new Error('No autenticado');
  }
  const data = await res.json().catch(() => ({}));
  // Cambio de contraseña o 2FA pendiente (server.js, requireLogin): si
  // alguien navega directo a una URL en vez de seguir el "destino" que
  // devuelve el login, esto la reencauza igual en vez de solo mostrar un
  // error de carga genérico.
  if (res.status === 403 && data.debeCambiarPassword) {
    window.location.href = '/cambiar-password.html';
    throw new Error('Cambio de contraseña pendiente');
  }
  if (res.status === 403 && data.requiereConfigurarTotp) {
    window.location.href = '/configurar-2fa.html';
    throw new Error('Verificación en dos pasos pendiente');
  }
  if (!res.ok) throw new Error(data.error || 'Error de red');
  return data;
}

function fmtMoney(n) {
  if (n === null || n === undefined) return '—';
  return '$' + Number(n).toLocaleString('es-CL');
}

function fmtFecha(iso) {
  if (!iso) return '—';
  const d = new Date(iso + 'T00:00:00');
  return d.toLocaleDateString('es-CL', { day: '2-digit', month: 'short', year: 'numeric' });
}

function badgeSemaforo(color, razon) {
  const letra = { verde: 'V', ambar: 'A', rojo: 'R' }[color] || '?';
  const etiqueta = { verde: 'En plazo', ambar: 'Por vencer', rojo: 'Atención' }[color] || color;
  return `<span class="badge ${color}" title="${(razon || '').replace(/"/g, '&quot;')}">${letra} · ${etiqueta}</span>`;
}

// Estado de carga/error consistente entre páginas: cada página deja un
// <div id="estadoCarga"></div> debajo del subtítulo, y lo usa así:
//   mostrarCargando('estadoCarga');
//   try { ... } catch (e) { mostrarErrorCarga('estadoCarga', e.message); return; }
//   ocultarCargando('estadoCarga');
function mostrarCargando(id, mensaje) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = `<div class="small muted">${mensaje || 'Cargando…'}</div>`;
}
function mostrarErrorCarga(id, mensaje) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = `<div class="small warn">⚠ No se pudo cargar la información${mensaje ? ' (' + mensaje + ')' : ''}. Intenta recargar la página.</div>`;
}
function ocultarCargando(id) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = '';
}

// ---------- checklist de documentos (compartido entre postulacion.html,
// panel-equipo.html y panel-director.html) ----------
function estadoBadge(estado) {
  const map = { reunido: 'verde', pendiente: 'gris', vencido: 'rojo' };
  return `<span class="badge ${map[estado] || 'gris'}">${estado}</span>`;
}
function auditoriaBadge(estado) {
  const map = { cumple: ['verde', 'Cumple'], no_cumple: ['rojo', 'No cumple'], falta: ['rojo', 'Falta'], sin_auditar: ['gris', 'Sin auditar'] };
  const [color, label] = map[estado] || ['gris', estado];
  return `<span class="badge ${color}">${label}</span>`;
}
// Problemas primero (no_cumple/falta), luego sin auditar, cumple al final.
const SEVERIDAD_AUDITORIA = { no_cumple: 0, falta: 0, sin_auditar: 1, cumple: 2 };
function ordenarPorSeveridad(docs) {
  return [...docs].sort((a, b) =>
    (SEVERIDAD_AUDITORIA[a.estado_auditoria] ?? 1) - (SEVERIDAD_AUDITORIA[b.estado_auditoria] ?? 1));
}

// Link para ver el archivo subido o descargar el borrador generado por IA —
// se usa en el checklist agregado (panel-equipo/panel-director), que antes
// solo mostraba estado/auditoría sin forma de ver el documento en sí.
function enlaceArchivo(d) {
  if (d.archivo_url) return `<a href="${d.archivo_url}" target="_blank">📎 Ver</a>`;
  if (d.contenido_generado) return `<a href="/api/documentos/${d.id}/descargar-borrador" target="_blank">⬇ Descargar</a>`;
  return '<span class="small muted">—</span>';
}

// Checklist agregado de TODAS las postulaciones, agrupado por postulación
// (Panel del equipo y Panel del director) — solo lectura, sin acciones;
// para reunir/auditar/subir un documento hay que entrar al detalle de la
// postulación (link en el título de cada grupo).
function renderChecklistDocumentos(containerId, documentosFlat) {
  const el = document.getElementById(containerId);
  if (!el) return;
  if (!documentosFlat.length) {
    el.innerHTML = '<p class="small muted">No hay documentos todavía.</p>';
    return;
  }
  const grupos = {};
  documentosFlat.forEach((d) => {
    if (!grupos[d.postulacion_id]) {
      grupos[d.postulacion_id] = {
        postulacion_id: d.postulacion_id, titulo: d.convocatoria_titulo,
        fuente: d.convocatoria_fuente, folio: d.folio, resultado: d.resultado, docs: [],
      };
    }
    grupos[d.postulacion_id].docs.push(d);
  });
  const lista = Object.values(grupos).map((g) => {
    g.docs = ordenarPorSeveridad(g.docs);
    g.conProblema = g.docs.filter((d) => d.estado_auditoria === 'no_cumple' || d.estado_auditoria === 'falta').length;
    g.sinAuditar = g.docs.filter((d) => d.estado_auditoria === 'sin_auditar').length;
    g.cumplen = g.docs.filter((d) => d.estado_auditoria === 'cumple').length;
    return g;
  });
  // Postulaciones con problemas primero, luego con pendientes de auditar,
  // el resto al final — mismo criterio de severidad que dentro de cada una.
  lista.sort((a, b) => (b.conProblema - a.conProblema) || (b.sinAuditar - a.sinAuditar));

  const totalConProblema = lista.reduce((s, g) => s + g.conProblema, 0);
  const totalSinAuditar = lista.reduce((s, g) => s + g.sinAuditar, 0);

  // Cada postulación es un <details> desplegable — nativo, con teclado y
  // lector de pantalla funcionando solo, sin JS adicional (evita repetir
  // el problema de accesibilidad por teclado que ya se encontró en el
  // kanban con divs clickeables). Las que tienen algo con problema se
  // abren solas; el resto queda plegado para no alargar la página.
  el.innerHTML = `
    <div class="doc-resumen">
      ${totalConProblema ? `<b class="warn" style="color:var(--red-text)">${totalConProblema} con problema</b> · ` : ''}
      ${totalSinAuditar} sin auditar · ${documentosFlat.length} documentos en ${lista.length} postulaciones
    </div>
    ${lista.map((g) => `
      <details class="doc-grupo" ${g.conProblema ? 'open' : ''} style="margin-top:10px; border-top:1px solid #EEF0F4; padding-top:10px;">
        <summary style="cursor:pointer; display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;">
          <a href="/postulacion.html?id=${g.postulacion_id}" style="font-weight:600">${g.titulo}</a>
          <span class="small muted">
            ${g.conProblema ? `<b class="warn" style="color:var(--red-text)">${g.conProblema} con problema</b> · ` : ''}
            ${g.sinAuditar} sin auditar · ${g.cumplen}/${g.docs.length} cumplen
          </span>
        </summary>
        <div class="table-scroll">
          <table style="margin-top:8px">
            <thead><tr><th>Documento</th><th>Fase</th><th>Responsable</th><th>Estado</th><th>Auditoría</th><th>Archivo</th></tr></thead>
            <tbody>
              ${g.docs.map((d) => `<tr>
                <td>${d.tipo}${d.sensible ? ' <span class="small muted">🔒</span>' : ''}</td>
                <td class="small muted">${d.fase === 'convenio' ? 'Convenio' : 'Postulación'}</td>
                <td class="small muted">${d.responsable_nombre || '—'}</td>
                <td>${estadoBadge(d.estado)}</td>
                <td>${auditoriaBadge(d.estado_auditoria)}</td>
                <td>${enlaceArchivo(d)}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </details>`).join('')}
  `;
}

async function initNav(activeKey) {
  let me;
  try {
    me = await api('/api/me');
  } catch (e) {
    return;
  }
  const nav = document.getElementById('topnav');
  if (!nav) return;

  // La página que más usa cada rol va primera (Efecto de posición de serie:
  // lo primero y lo último de una lista es lo que mejor se recuerda) — antes
  // "Monitoreo" iba siempre primero aunque no fuera la página principal de
  // nadie en particular.
  const links = [];
  if (me.rol === 'equipo') {
    links.push({ key: 'equipo', label: 'Mis postulaciones', href: '/panel-equipo.html' });
  } else {
    // director y admin comparten la misma vista de más alto nivel por ahora
    // -- la Fase D (tab Configuración) es la que le da a admin su propia
    // pantalla dedicada de gestión de usuarios.
    links.push({ key: 'director', label: 'Panel del director', href: '/panel-director.html' });
  }
  links.push({ key: 'monitoreo', label: 'Monitoreo', href: '/monitoreo.html' });
  links.push({ key: 'calendario', label: 'Calendario', href: '/calendario.html' });
  if (me.gestionar_usuarios) {
    links.push({ key: 'admin', label: 'Configuración', href: '/administracion.html' });
  }

  nav.innerHTML = `
    <span class="brand">Agente de Concursos</span>
    ${links.map((l) => `<a class="navlink ${l.key === activeKey ? 'active' : ''}" href="${l.href}">${l.label}</a>`).join('')}
    <form id="navBuscarForm" class="nav-buscar" role="search" autocomplete="off">
      <input type="search" id="navBuscarInput" placeholder="Buscar postulación o documento…" aria-label="Buscar postulaciones o documentos">
    </form>
    <span class="spacer"></span>
    <span class="acct" id="acctToggle">${me.nombre} · ${me.rol} ⌄
      <div class="acct-menu" id="acctMenu"><button id="btnLogout">Cerrar sesión</button></div>
    </span>
  `;
  document.getElementById('acctToggle').addEventListener('click', (e) => {
    document.getElementById('acctMenu').classList.toggle('open');
    e.stopPropagation();
  });
  document.addEventListener('click', () => {
    const menu = document.getElementById('acctMenu');
    if (menu) menu.classList.remove('open');
  });
  document.getElementById('btnLogout').addEventListener('click', async () => {
    await api('/api/logout', { method: 'POST' });
    window.location.href = '/login.html';
  });
  const buscarForm = document.getElementById('navBuscarForm');
  buscarForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const q = document.getElementById('navBuscarInput').value.trim();
    if (q.length >= 2) window.location.href = '/buscar.html?q=' + encodeURIComponent(q);
  });
  return me;
}

// Exportar una tabla a CSV (Excel la abre directo) — usado en los reportes
// del panel del director. BOM al inicio para que Excel en Windows detecte
// UTF-8 y no rompa las tildes/ñ.
function descargarCSV(nombreArchivo, encabezados, filas) {
  const escapar = (v) => {
    const s = v === null || v === undefined ? '' : String(v);
    return /[",\n;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const csv = [encabezados, ...filas].map(fila => fila.map(escapar).join(';')).join('\r\n');
  const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = nombreArchivo;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

// Formatea fecha+hora de un comentario/versión para mostrar en las listas.
function fmtFechaHora(iso) {
  if (!iso) return '—';
  const d = new Date(iso.includes('T') ? iso : iso.replace(' ', 'T') + 'Z');
  return d.toLocaleString('es-CL', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function tiempoRelativo(iso) {
  const d = new Date(iso.replace(' ', 'T') + 'Z');
  const mins = Math.round((Date.now() - d.getTime()) / 60000);
  if (mins < 60) return `hace ${mins} min`;
  const horas = Math.round(mins / 60);
  if (horas < 24) return `hace ${horas} h`;
  return `hace ${Math.round(horas / 24)} d`;
}

// Tarjeta de notificaciones — usada por panel-equipo.html y panel-director.html.
function renderNotificaciones(containerId, notificaciones) {
  const notifsEl = document.getElementById(containerId);
  if (!notifsEl) return;
  if (notificaciones.length === 0) {
    notifsEl.innerHTML = '<span class="muted small">Sin notificaciones.</span>';
    return;
  }
  notifsEl.innerHTML = notificaciones.map((n) => `
    <div class="notif-item ${n.leida ? '' : 'no-leida'}" data-id="${n.id}">
      <span class="msg">${n.leida ? '' : '● '}${n.mensaje}</span>
      <span class="cuando">${tiempoRelativo(n.creado_en)}</span>
    </div>`).join('');
  notifsEl.querySelectorAll('.notif-item').forEach((el) => {
    el.addEventListener('click', async () => {
      await api(`/api/notificaciones/${el.dataset.id}/leida`, { method: 'POST' });
      const notif = notificaciones.find(n => String(n.id) === el.dataset.id);
      if (notif && notif.postulacion_id) window.location.href = `/postulacion.html?id=${notif.postulacion_id}`;
    });
  });
}
