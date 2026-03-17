// frontend/password_manager/src/components/login.tsx
import { useState } from 'react';
import axios from 'axios';
import { hashPassword } from '../utils/crypto'; // Reuse your utility

export default function Login() {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [status, setStatus] = useState<string>('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus('Authenticating...');
    
    try {
      const secureHash = await hashPassword(password);
      const response = await axios.post('http://localhost:8080/api/v1/auth/login', {
        username: username,
        password_hash: secureHash
      });
      
      const token = response.data.token;

      // Store the JWT "Passport" in the browser
      localStorage.setItem('vault_token', token);
      setStatus(`Logged in!`);
      
      // We will add a redirect to the Vault view here in Step 3
    } catch (err: any) {
      const errorMsg = err.response?.data || "Login failed";
      setStatus(`Error: ${errorMsg}`);
    }
  };

  return (
    <div className="p-6 max-w-sm mx-auto bg-slate-900 rounded-xl shadow-md space-y-4 border border-slate-700">
      <h2 className="text-xl font-bold text-emerald-400">Vault Login</h2>
      <form onSubmit={handleLogin} className="flex flex-col gap-4">
        <input 
          type="text" 
          placeholder="Username"
          className="p-2 rounded bg-slate-800 text-white border border-slate-600"
          onChange={(e) => setUsername(e.target.value)} 
        />
        <input 
          type="password" 
          placeholder="Master Password"
          className="p-2 rounded bg-slate-800 text-white border border-slate-600"
          onChange={(e) => setPassword(e.target.value)} 
        />
        <button type="submit" className="bg-emerald-500 hover:bg-emerald-600 text-white font-bold py-2 px-4 rounded transition-colors">
          Open Vault
        </button>
      </form>
      {status && <p className="text-sm text-slate-400 italic">{status}</p>}
    </div>
  );
}