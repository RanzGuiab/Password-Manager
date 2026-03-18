// frontend/password_manager/src/components/register.tsx
import { useState } from 'react';
import axios from 'axios';
import { hashPassword } from '../utils/crypto';

// Define the "contract" for this component's props
interface RegisterProps {
  onRegisterSuccess: () => void;
}

// Simple password strength check
const getStrength = (password: string) => {
  let strength = 0;
  if (password.length > 8) strength++;
  if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength++;
  if (password.match(/[0-9]/)) strength++;
  if (password.match(/[^a-zA-Z0-9]/)) strength++;
  return strength;
};

const strengthLevels = [
  { text: 'Too weak', color: 'bg-red-500' },
  { text: 'Could be stronger', color: 'bg-orange-500' },
  { text: 'Good', color: 'bg-yellow-500' },
  { text: 'Strong', color: 'bg-green-500' },
  { text: 'Very Strong', color: 'bg-emerald-500' }
];

function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    let binary = '';
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

export default function Register({ onRegisterSuccess }: RegisterProps) {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [status, setStatus] = useState<string>('');
  const passwordStrength = getStrength(password);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (passwordStrength < 3) {
      setStatus("Password is too weak. Please choose a stronger one.");
      return;
    }
    setStatus('Generating salt and hashing password...');
    
    try {
      // 1. Generate a random salt for the new user
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      
      // 2. Create the login hash (SENT to server for auth)
      const loginHash = await hashPassword(password);

      // 3. Send the public parts to the backend
      await axios.post('http://localhost:8080/api/v1/auth/register', {
        username,
        password_hash: loginHash
      });

      // 4. Store the salt locally for future key derivations
      localStorage.setItem(`salt_${username}`, arrayBufferToBase64(salt));
      
      setStatus('Registration successful! Please log in.');
      onRegisterSuccess();
    } catch (err: any) {
      setStatus(`Error: ${err.response?.data?.error || "Registration failed"}`);
    }
  };

  return (
    <div className="p-6 max-w-sm mx-auto bg-slate-900 rounded-xl border border-slate-700">
      <h2 className="text-xl font-bold text-sky-400 mb-4">Create Your Vault</h2>
      <form onSubmit={handleRegister} className="flex flex-col gap-4">
        <input 
          type="text" 
          placeholder="Username" 
          className="p-2 rounded bg-slate-800 border border-slate-700" 
          onChange={(e) => setUsername(e.target.value)} 
          value={username}
        />
        <div className="relative">
          <input 
            type="password" 
            placeholder="Master Password" 
            className="p-2 w-full rounded bg-slate-800 border border-slate-700" 
            onChange={(e) => setPassword(e.target.value)} 
            value={password}
          />
          {password.length > 0 && (
            <div className="mt-2">
              <div className="w-full bg-slate-700 rounded-full h-2">
                <div 
                  className={`h-2 rounded-full ${strengthLevels[passwordStrength].color}`} 
                  style={{ width: `${(passwordStrength / 4) * 100}%` }}
                ></div>
              </div>
              <p className="text-xs text-right mt-1 text-slate-400">{strengthLevels[passwordStrength].text}</p>
            </div>
          )}
        </div>
        <button type="submit" className="bg-sky-500 hover:bg-sky-600 py-2 rounded font-bold transition-colors">Create Account</button>
      </form>
      {status && <p className="text-sm mt-2 italic text-slate-400">{status}</p>}
    </div>
  );
}