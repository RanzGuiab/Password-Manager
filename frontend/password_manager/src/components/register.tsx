// frontend/password_manager/src/components/register.tsx
import { useState } from 'react';
import axios from 'axios';
import { hashPassword } from '../utils/crypto';

// Define the "contract" for this component's props
interface RegisterProps {
  onRegisterSuccess: () => void;
}

export default function Register({ onRegisterSuccess }: RegisterProps) {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [status, setStatus] = useState<string>('');

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus('Hashing and sending...');
    
    try {
      const secureHash = await hashPassword(password);
      await axios.post('http://localhost:8080/api/v1/auth/register', {
        username,
        password_hash: secureHash
      });
      
      setStatus('Registration successful!');
      onRegisterSuccess(); // Trigger the view switch in App.tsx
    } catch (err: any) {
      setStatus(`Error: ${err.response?.data || "Registration failed"}`);
    }
  };

  return (
    <div className="p-6 max-w-sm mx-auto bg-slate-900 rounded-xl border border-slate-700">
      <h2 className="text-xl font-bold text-sky-400 mb-4">Vault Registration</h2>
      <form onSubmit={handleRegister} className="flex flex-col gap-4">
        <input type="text" placeholder="Username" className="p-2 rounded bg-slate-800" onChange={(e) => setUsername(e.target.value)} />
        <input type="password" placeholder="Master Password" className="p-2 rounded bg-slate-800" onChange={(e) => setPassword(e.target.value)} />
        <button type="submit" className="bg-sky-500 py-2 rounded font-bold">Register Account</button>
      </form>
      {status && <p className="text-sm mt-2 italic text-slate-400">{status}</p>}
    </div>
  );
}