// frontend/password_manager/src/components/login.tsx
import { useState } from 'react';
import { hashPassword, deriveKey } from '../utils/crypto';
import { useEncryptionKey } from '../context/EncryptionKeyContext';
import api from '../lib/api';

interface LoginProps {
  onLoginSuccess: (key: CryptoKey) => void;
  hasActiveSession?: boolean;
}

function base64ToArrayBuffer(base64: string): Uint8Array {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

export default function Login({ onLoginSuccess, hasActiveSession = false }: LoginProps) {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [status, setStatus] = useState<string>('');
  const { setEncryptionKey } = useEncryptionKey();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();

    const normalizedUsername = username.trim();
    if (!normalizedUsername || !password) {
      setStatus("Username and password are required.");
      return;
    }

    try {
      const saltBase64 = localStorage.getItem(`salt_${normalizedUsername}`);
      if (!saltBase64) {
        setStatus("Login failed: Username not found or salt missing.");
        return;
      }
      const salt = base64ToArrayBuffer(saltBase64);

      const existingToken = localStorage.getItem('vault_token');

      if (hasActiveSession && existingToken) {
        setStatus("Session found. Unlocking vault...");
        await api.get('/api/v1/auth/session');
      } else {
        setStatus("Authenticating and deriving key...");
        const passwordHash = await hashPassword(password);

        const res = await api.post('/api/v1/auth/login', {
          username: normalizedUsername,
          password_hash: passwordHash,
        });

        const token = res.data?.token as string | undefined;
        if (!token) throw new Error('missing auth token');
        localStorage.setItem('vault_token', token);
      }

      const newEncryptionKey = await deriveKey(password, salt);
      setEncryptionKey(newEncryptionKey);
      onLoginSuccess(newEncryptionKey);
      setStatus("Unlocked.");
    } catch (err: any) {
      if (err?.response?.status === 401) {
        localStorage.removeItem('vault_token');
      }
      setStatus(`Error: ${err?.response?.data?.error || err?.message || "Invalid credentials"}`);
    }
  };

  const token = localStorage.getItem('vault_token');
  const unlockMode = hasActiveSession || !!token;
  const message = unlockMode ? "Unlock Your Vault" : "Vault Login";

  return (
    <div className="p-6 max-w-sm mx-auto bg-slate-900 rounded-xl border border-slate-700">
      <h2 className="text-xl font-bold text-emerald-400 mb-4">{message}</h2>
      <form onSubmit={handleLogin} className="flex flex-col gap-4">
        <input 
          type="text" 
          placeholder="Username" 
          className="p-2 rounded bg-slate-800 border border-slate-700" 
          onChange={(e) => setUsername(e.target.value)} 
          value={username}
        />
        <input 
          type="password" 
          placeholder="Master Password" 
          className="p-2 rounded bg-slate-800 border border-slate-700" 
          onChange={(e) => setPassword(e.target.value)} 
          value={password}
        />
        <button type="submit" className="bg-emerald-500 hover:bg-emerald-600 py-2 rounded font-bold transition-colors">
          {unlockMode ? "Unlock" : "Open Vault"}
        </button>
      </form>
      {status && <p className="text-sm mt-2 italic text-slate-400">{status}</p>}
    </div>
  );
}