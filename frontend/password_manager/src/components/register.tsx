import { useState } from 'react';
// @ts-ignore
import axios from 'axios'; 

export default function Register() {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [status, setStatus] = useState<string>('');

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus('Sending...');
    
    try {
      // Direct call to your Go Backend
      const response = await axios.post('http://localhost:8080/api/v1/auth/register', {
        username: username,
        password_hash: password // We will hash this in Phase 6
      });
      
      setStatus(`Success: ${response.data}`);
    } catch (err: any) {
      // This catches the 409 Conflict from your Go DB check
      const errorMsg = err.response?.data || "Registration failed";
      setStatus(`Error: ${errorMsg}`);
    }
  };

  return (
    <div className="p-6 max-w-sm mx-auto bg-slate-900 rounded-xl shadow-md space-y-4 border border-slate-700">
      <h2 className="text-xl font-bold text-sky-400">Vault Registration</h2>
      <form onSubmit={handleRegister} className="flex flex-col gap-4">
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
        <button type="submit" className="bg-sky-500 hover:bg-sky-600 text-white font-bold py-2 px-4 rounded">
          Register Account
        </button>
      </form>
      {status && <p className="text-sm text-slate-400 italic">{status}</p>}
    </div>
  );
}