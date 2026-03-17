// frontend/password_manager/src/App.tsx
import { useState } from 'react'
import Register from './components/register'
import Login from './components/login'
import './App.css'

function App() {
  const [view, setView] = useState<'login' | 'register'>('login');

  return (
    <div className="min-h-screen bg-slate-950 text-white flex flex-col items-center justify-center space-y-6">
      <div className="flex space-x-4 mb-4">
        <button 
          onClick={() => setView('login')}
          className={`px-4 py-2 rounded ${view === 'login' ? 'bg-emerald-500 text-black' : 'bg-slate-800'}`}
        >
          Login
        </button>
        <button 
          onClick={() => setView('register')}
          className={`px-4 py-2 rounded ${view === 'register' ? 'bg-sky-500 text-black' : 'bg-slate-800'}`}
        >
          Register
        </button>
      </div>

      {view === 'login' ? <Login /> : <Register />}
    </div>
  )
}

export default App