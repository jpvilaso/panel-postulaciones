// Política de contraseña alineada a NIST SP 800-63B Revisión 4 (2025):
// sin reglas de composición obligatorias, largo mínimo bajo porque hay 2FA
// (TOTP) como segundo factor, largo máximo generoso para permitir
// passphrases, y verificación contra contraseñas filtradas en vez de reglas
// de "mayúscula+número+símbolo" que la evidencia dice que no ayudan.
//
// El chequeo de contraseñas filtradas se hace al crear o cambiar una
// contraseña (no en cada login) -- eso evita depender de una API externa
// en el camino crítico del login, y ya cubre el momento que NIST señala
// como el importante: cuando la persona elige la contraseña.

const crypto = require('crypto');

const MIN_LARGO = 8; // NIST exige 15 si la contraseña es el único factor; acá basta 8 porque hay TOTP.
const MAX_LARGO = 64;

function validarLargo(password) {
  if (typeof password !== 'string' || password.length === 0) {
    return { valido: false, motivo: 'La contraseña es obligatoria.' };
  }
  if (password.length < MIN_LARGO) {
    return { valido: false, motivo: `Debe tener al menos ${MIN_LARGO} caracteres.` };
  }
  if (password.length > MAX_LARGO) {
    return { valido: false, motivo: `No puede superar los ${MAX_LARGO} caracteres.` };
  }
  return { valido: true };
}

// Consulta la API "Pwned Passwords" (haveibeenpwned) con k-anonimato: solo
// se envían los primeros 5 caracteres del hash SHA-1 de la contraseña, nunca
// la contraseña ni el hash completo. El header Add-Padding pide respuestas
// con líneas de relleno (conteo 0) para que ni el tamaño de la respuesta
// filtre información -- por eso se descartan las líneas con conteo 0.
async function passwordComprometida(password) {
  try {
    const sha1 = crypto.createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
    const prefijo = sha1.slice(0, 5);
    const sufijo = sha1.slice(5);
    const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefijo}`, {
      headers: { 'Add-Padding': 'true' },
    });
    if (!resp.ok) throw new Error(`Pwned Passwords respondió ${resp.status}`);
    const texto = await resp.text();
    return texto.split('\n').some((linea) => {
      const [suf, conteo] = linea.trim().split(':');
      return suf === sufijo && Number(conteo) > 0;
    });
  } catch (err) {
    // Fail-open: un problema de red hacia un servicio externo no debe
    // impedir que alguien cambie su contraseña. Se deja registrado igual.
    console.warn('[passwordPolicy] no se pudo consultar Pwned Passwords, se continúa sin bloquear:', err.message);
    return false;
  }
}

module.exports = { validarLargo, passwordComprometida, MIN_LARGO, MAX_LARGO };
