const PBKDF2_ITERATIONS = 100_000;
const AES_KEY_LENGTH = 256;
const IV_LENGTH = 12;

function toArrayBuffer(input: ArrayBuffer | ArrayBufferView): ArrayBuffer {
  if (input instanceof ArrayBuffer) return input;

  const view = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  const out = new Uint8Array(view.byteLength);
  out.set(view);
  return out.buffer;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function hashPassword(password: string): Promise<string> {
  const passwordBytes = new TextEncoder().encode(password);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', toArrayBuffer(passwordBytes));
  return bytesToBase64(new Uint8Array(hashBuffer));
}

export async function deriveKey(password: string, salt: Uint8Array | ArrayBuffer): Promise<CryptoKey> {
  const passwordBytes = new TextEncoder().encode(password);

  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    toArrayBuffer(passwordBytes),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const saltBytes = salt instanceof Uint8Array ? salt : new Uint8Array(salt);

  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toArrayBuffer(saltBytes),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encrypt(
  key: CryptoKey,
  plaintext: string
): Promise<{ encrypted: string; iv: string }> {
  const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const plaintextBytes = new TextEncoder().encode(plaintext);

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(plaintextBytes)
  );

  return {
    encrypted: bytesToBase64(new Uint8Array(encryptedBuffer)),
    iv: bytesToBase64(iv),
  };
}

export async function decrypt(
  key: CryptoKey,
  encryptedBase64: string,
  ivBase64: string
): Promise<string> {
  const encryptedBytes = base64ToBytes(encryptedBase64);
  const ivBytes = base64ToBytes(ivBase64);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(ivBytes) },
    key,
    toArrayBuffer(encryptedBytes)
  );

  return new TextDecoder().decode(decryptedBuffer);
}