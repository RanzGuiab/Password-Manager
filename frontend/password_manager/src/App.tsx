import { useState, useEffect, useCallback } from 'react';
import './App.css';
import Register from './components/register';
import Login from './components/login';
import Vault from './components/Vault';
import { useEncryptionKey } from './context/EncryptionKeyContext';
import api from './lib/api';
import axios from 'axios';

const INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15 minutes

function App() {
  const [view, setView] = useState<'login' | 'register'>('login');
  const { encryptionKey, setEncryptionKey } = useEncryptionKey();
  const [authChecked, setAuthChecked] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const handleLock = useCallback(() => {
    setEncryptionKey(null);
    setView('login');
  }, [setEncryptionKey]);

  const handleLogout = useCallback(() => {
    localStorage.removeItem('vault_token');
    setIsAuthenticated(false);
    setEncryptionKey(null);
    setView('login');
  }, [setEncryptionKey]);

  useEffect(() => {
    let inactivityTimer: number;

    const resetTimer = () => {
      clearTimeout(inactivityTimer);
      if (isAuthenticated && encryptionKey) {
        inactivityTimer = window.setTimeout(() => {
          alert("Session locked due to inactivity. Unlock again.");
          handleLock();
        }, INACTIVITY_TIMEOUT);
      }
    };

    window.addEventListener('mousemove', resetTimer);
    window.addEventListener('keypress', resetTimer);
    resetTimer();

    return () => {
      clearTimeout(inactivityTimer);
      window.removeEventListener('mousemove', resetTimer);
      window.removeEventListener('keypress', resetTimer);
    };
  }, [isAuthenticated, encryptionKey, handleLock]);

  useEffect(() => {
    const token = localStorage.getItem('vault_token');
    if (!token) {
      setIsAuthenticated(false);
      setAuthChecked(true);
      return;
    }

    api.get('/api/v1/auth/session')
      .then(() => {
        setIsAuthenticated(true);
        setView('login'); // refresh => unlock flow
      })
      .catch((err: unknown) => {
        if (axios.isAxiosError(err) && err.response?.status === 401) {
          localStorage.removeItem('vault_token');
          setIsAuthenticated(false);
          return;
        }
        // transient network error: keep token
        setIsAuthenticated(true);
      })
      .finally(() => setAuthChecked(true));
  }, []);

  const handleRegisterSuccess = () => {
    setView('login');
  };

  const handleLoginSuccess = (key: CryptoKey) => {
    setEncryptionKey(key);
    setIsAuthenticated(true);
  };

  if (!authChecked) {
    return (
      <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center">
        Checking session...
      </div>
    );
  }

  if (isAuthenticated && encryptionKey) {
    return (
      <div className="min-h-screen bg-slate-950 text-white flex flex-col items-center justify-center p-4">
        <Vault onLogout={handleLogout} />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-white flex flex-col items-center justify-center p-4">
      <div className="text-center animate-fade-in">
        <h1 className="text-4xl font-bold text-sky-400 mb-2">Zero-Knowledge Password Vault</h1>
        <p className="text-slate-400 mb-8">
          {isAuthenticated
            ? <>Session active. Enter master password to <span className="font-bold text-emerald-400">unlock</span>.</>
            : <>Your secrets are safe because only <span className="font-bold text-emerald-400">you</span> can decrypt them.</>}
        </p>

        <div className="flex space-x-4 mb-8 justify-center">
          <button
            onClick={() => setView('login')}
            className={`px-4 py-2 rounded font-semibold ${view === 'login' ? 'bg-emerald-500 text-black' : 'bg-slate-800 hover:bg-slate-700'}`}
          >
            {isAuthenticated ? 'Unlock' : 'Login'}
          </button>

          {!isAuthenticated && (
            <button
              onClick={() => setView('register')}
              className={`px-4 py-2 rounded font-semibold ${view === 'register' ? 'bg-sky-500 text-black' : 'bg-slate-800 hover:bg-slate-700'}`}
            >
              Register
            </button>
          )}
        </div>

        {view === 'login' && <Login onLoginSuccess={handleLoginSuccess} hasActiveSession={isAuthenticated} />}
        {!isAuthenticated && view === 'register' && <Register onRegisterSuccess={handleRegisterSuccess} />}

        {isAuthenticated && (
          <button onClick={handleLogout} className="mt-6 text-sm text-red-400 hover:text-red-300 underline">
            Logout
          </button>
        )}
      </div>
    </div>
  );
}

export default App