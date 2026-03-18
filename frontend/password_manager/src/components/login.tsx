// frontend/password_manager/src/components/login.tsx
import { useState } from 'react';
import axios from 'axios';
import { hashPassword } from '../utils/crypto';

interface LoginProps {
  onLoginSuccess: () => void;
}

export default function Login({ onLoginSuccess }: LoginProps) {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [status, setStatus] = useState<string>('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const secureHash = await hashPassword(password);
      const res = await axios.post('http://localhost:8080/api/v1/auth/login', {
        username,
        password_hash: secureHash
      });
      
      localStorage.setItem('vault_token', res.data.token);
      onLoginSuccess(); // Switch to Vault view
    } catch (err: any) {
      setStatus("Invalid credentials");
    }
  };

  return (
    <div className="p-6 max-w-sm mx-auto bg-slate-900 rounded-xl border border-slate-700">
      <h2 className="text-xl font-bold text-emerald-400 mb-4">Vault Login</h2>
      <form onSubmit={handleLogin} className="flex flex-col gap-4">
        <input type="text" placeholder="Username" className="p-2 rounded bg-slate-800" onChange={(e) => setUsername(e.target.value)} />
        <input type="password" placeholder="Master Password" className="p-2 rounded bg-slate-800" onChange={(e) => setPassword(e.target.value)} />
        <button type="submit" className="bg-emerald-500 py-2 rounded font-bold">Open Vault</button>
      </form>
      {status && <p className="text-sm mt-2 italic text-red-400">{status}</p>}
    </div>
  );
}