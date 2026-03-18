import { useEffect, useState } from 'react';
import axios from 'axios';

type VaultProps = {
  onLogout: () => void;
};

export default function Vault({ onLogout }: VaultProps) {
  const [secrets, setSecrets] = useState<any[]>([]);
  const token = localStorage.getItem('vault_token');

  const handleLogout = () => {
    localStorage.removeItem('vault_token');
    onLogout();
  };

  useEffect(() => {
    const fetchSecrets = async () => {
      const res = await axios.get('http://localhost:8080/api/v1/vault', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSecrets(res.data);
    };

    if (token) {
      fetchSecrets();
    }
  }, [token]);

  return (
    <div className="p-6 bg-slate-900 rounded-xl border border-slate-700 w-full max-w-4xl">
      <div className="mb-6 flex items-center justify-between">
        <h2 className="text-2xl font-bold text-sky-400">Your Secure Vault</h2>
        <button
          onClick={handleLogout}
          className="bg-red-600 px-3 py-1 rounded text-sm hover:bg-red-500"
        >
          Logout
        </button>
      </div>

      <div className="grid gap-4">
        {secrets.map((s: any) => (
          <div key={s.id} className="p-4 bg-slate-800 rounded border border-slate-700 flex justify-between items-center">
            <div className="flex flex-col">
              <span className="text-emerald-400 font-bold">{s.site_name}</span>
              <span className="text-slate-400 text-sm">{s.site_username}</span>
            </div>
            <div className="flex gap-2">
              <input
                type="password"
                value={s.password}
                readOnly
                className="bg-slate-700 p-1 rounded text-sm w-32 border border-slate-600"
              />
              <button
                onClick={() => navigator.clipboard.writeText(s.password)}
                className="bg-sky-600 px-3 py-1 rounded text-xs hover:bg-sky-500"
              >
                Copy
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}