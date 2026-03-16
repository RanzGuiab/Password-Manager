import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx' // Ensure the .tsx extension is present
import './index.css' // Your Tailwind styles

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)