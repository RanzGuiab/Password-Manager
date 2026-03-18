// frontend/password_manager/src/components/login.tsx
import { useState } from 'react';
import axios from 'axios';
import { hashPassword, deriveKey } from '../utils/crypto';
import { useEncryptionKey } from '../context/EncryptionKeyContext';

interface LoginProps {
  onLoginSuccess: (key: CryptoKey) => void;
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

export default function Login({ onLoginSuccess }: LoginProps) {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [status, setStatus] = useState<string>('');
  const { setEncryptionKey } = useEncryptionKey();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus("Authenticating and deriving key...");

    try {
      // 1. Retrieve the user's salt from local storage
      const saltBase64 = localStorage.getItem(`salt_${username}`);
      if (!saltBase64) {
        setStatus("Login failed: Username not found or salt missing.");
        return;
      }
      const salt = base64ToArrayBuffer(saltBase64);

      // 2. Hash the password for login verification
      const loginHash = await hashPassword(password);
      
      // 3. Send credentials to the server
      const res = await axios.post('http://localhost:8080/api/v1/auth/login', {
        username,
        password_hash: loginHash
      });
      
      // If server auth is successful, THEN we derive the key for local use
      setStatus("Login successful! Deriving encryption key...");
      const newEncryptionKey = await deriveKey(password, salt);
      
      // 4. Store the session token
      localStorage.setItem('vault_token', res.data.token);
      
      // 5. Set the key in the global context and switch view
      setEncryptionKey(newEncryptionKey);
      onLoginSuccess(newEncryptionKey);
    } catch (err: any) {
      console.error(err);
      setStatus(`Error: ${err.response?.data?.error || "Invalid credentials"}`);
    }
  };

  const token = localStorage.getItem('vault_token');
  const message = token ? "Unlock Your Vault" : "Vault Login";

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
            {token ? "Unlock" : "Open Vault"}
        </button>
      </form>
      {status && <p className="text-sm mt-2 italic text-slate-400">{status}</p>}
    </div>
  );
}