import { useState, useEffect, useCallback } from 'react';
import './App.css';
import Register from './components/register';
import Login from './components/login';
import Vault from './components/Vault';
import { useEncryptionKey } from './context/EncryptionKeyContext';

const INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15 minutes

function App() {
  const [view, setView] = useState<'login' | 'register' | 'vault'>('login');
  const { encryptionKey, setEncryptionKey } = useEncryptionKey();
  
  const handleLogout = useCallback(() => {
    localStorage.removeItem('vault_token');
    setEncryptionKey(null); // Wipe the key from context
    setView('login');
  }, [setEncryptionKey]);

  // Auto-lock mechanism
  useEffect(() => {
    let inactivityTimer: number;

    const resetTimer = () => {
      clearTimeout(inactivityTimer);
      if (encryptionKey) { // Only run the timer if logged in
        inactivityTimer = window.setTimeout(() => {
          alert("Session timed out due to inactivity. Please log in again.");
          handleLogout();
        }, INACTIVITY_TIMEOUT);
      }
    };

    // Reset timer on any user interaction
    window.addEventListener('mousemove', resetTimer);
    window.addEventListener('keypress', resetTimer);
    
    resetTimer(); // Initial setup

    return () => {
      clearTimeout(inactivityTimer);
      window.removeEventListener('mousemove', resetTimer);
      window.removeEventListener('keypress', resetTimer);
    };
  }, [encryptionKey, handleLogout]);


  // Check for existing session on load
  useEffect(() => {
    const token = localStorage.getItem('vault_token');
    if (token && !encryptionKey) {
      // User has a session but no key, prompt for password
      setView('login');
    } else if (!token) {
      setView('login');
    }
  }, [encryptionKey]);

  const handleRegisterSuccess = () => {
    setView('login'); // After registration, send them to login to derive key
  };

  const handleLoginSuccess = (key: CryptoKey) => {
    setEncryptionKey(key);
    setView('vault');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-white flex flex-col items-center justify-center p-4">
      {view !== 'vault' ? (
        <div className="text-center animate-fade-in">
            <h1 className="text-4xl font-bold text-sky-400 mb-2">Zero-Knowledge Password Vault</h1>
            <p className="text-slate-400 mb-8">Your secrets are safe because only <span className="font-bold text-emerald-400">you</span> can decrypt them.</p>
            <div className="flex space-x-4 mb-8 justify-center">
                <button onClick={() => setView('login')} className={`px-4 py-2 rounded font-semibold ${view === 'login' ? 'bg-emerald-500 text-black' : 'bg-slate-800 hover:bg-slate-700'}`}>Login</button>
                <button onClick={() => setView('register')} className={`px-4 py-2 rounded font-semibold ${view === 'register' ? 'bg-sky-500 text-black' : 'bg-slate-800 hover:bg-slate-700'}`}>Register</button>
            </div>
            
            {view === 'login' && <Login onLoginSuccess={handleLoginSuccess} />}
            {view === 'register' && <Register onRegisterSuccess={handleRegisterSuccess} />}

        </div>
      ) : (
         encryptionKey && <Vault onLogout={handleLogout} />
      )}
    </div>
  )
}

export default App