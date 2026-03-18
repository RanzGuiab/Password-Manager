import { useState, useEffect } from 'react'
import './App.css'
import Register from './components/register'
import Login from './components/login'
import Vault from './components/Vault'

function App() {
  const [view, setView] = useState<'login' | 'register' | 'vault'>('login');

  // Check for existing session on load
  useEffect(() => {
    const token = localStorage.getItem('vault_token');
    if (token) {
      setView('vault');
    }
  }, []);

  const handleLogout = () => {
    setView('login');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-white flex flex-col items-center justify-center p-4">
      {view !== 'vault' && (
        <div className="flex space-x-4 mb-8">
          <button onClick={() => setView('login')} className={`px-4 py-2 rounded ${view === 'login' ? 'bg-emerald-500 text-black' : 'bg-slate-800'}`}>Login</button>
          <button onClick={() => setView('register')} className={`px-4 py-2 rounded ${view === 'register' ? 'bg-sky-500 text-black' : 'bg-slate-800'}`}>Register</button>
        </div>
      )}

      {view === 'login' && <Login onLoginSuccess={() => setView('vault')} />}
      {view === 'register' && <Register onRegisterSuccess={() => setView('login')} />}
      {view === 'vault' && <Vault onLogout={handleLogout} />}
    </div>
  )
}

export default App