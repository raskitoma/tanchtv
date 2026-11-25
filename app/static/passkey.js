// Passkey (WebAuthn) helpers shared by the login page and "My account".
const b64uToBuf = s => {
  s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer;
};
const bufToB64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export const passkeysSupported = () => !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);

async function postJSON(url, data) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data || {}) });
  let j = {}; try { j = await r.json(); } catch {}
  if (!r.ok) throw new Error(j.error || 'Something went wrong.');
  return j;
}

function friendly(err) {
  if (err && err.name === 'NotAllowedError') return new Error('Passkey request was cancelled or timed out.');
  if (err && err.name === 'InvalidStateError') return new Error('This device already has a passkey for your account.');
  return err;
}

/** Create a passkey for the signed-in user. */
export async function registerPasskey(name) {
  const { flow, options: o } = await postJSON('/api/passkeys/register/options');
  const publicKey = {
    ...o,
    challenge: b64uToBuf(o.challenge),
    user: { ...o.user, id: b64uToBuf(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map(c => ({ ...c, id: b64uToBuf(c.id) })),
  };
  let cred;
  try { cred = await navigator.credentials.create({ publicKey }); } catch (e) { throw friendly(e); }
  const credential = {
    id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
  };
  return postJSON('/api/passkeys/register/verify', { flow, credential, name });
}

/** Sign in with any passkey stored for this site (no username needed). */
export async function signInWithPasskey() {
  const { flow, options: o } = await postJSON('/api/passkeys/login/options');
  const publicKey = {
    ...o,
    challenge: b64uToBuf(o.challenge),
    allowCredentials: (o.allowCredentials || []).map(c => ({ ...c, id: b64uToBuf(c.id) })),
  };
  let cred;
  try { cred = await navigator.credentials.get({ publicKey }); } catch (e) { throw friendly(e); }
  const credential = {
    id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      signature: bufToB64u(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : undefined,
    },
  };
  return postJSON('/api/passkeys/login/verify', { flow, credential });
}
