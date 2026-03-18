// frontend/password_manager/src/components/AddSecretForm.tsx
import { useState } from 'react';
import axios from 'axios';
import { encrypt } from '../utils/crypto';
import { useEncryptionKey } from '../context/EncryptionKeyContext';

interface AddSecretFormProps {
    onSecretAdded: () => void;
}

export default function AddSecretForm({ onSecretAdded }: AddSecretFormProps) {
    const { encryptionKey } = useEncryptionKey(); // Use context
    const [siteName, setSiteName] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [status, setStatus] = useState('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!encryptionKey) {
            setStatus("Error: Encryption key is not available.");
            return;
        }

        const token = localStorage.getItem('vault_token');
        if (!token) {
            setStatus("Session expired. Please log in again.");
            return;
        }

        if (!siteName.trim() || !username.trim() || !password) {
            setStatus("All fields are required.");
            return;
        }

        setStatus('Encrypting and saving...');

        try {
            const { encrypted, iv } = await encrypt(encryptionKey, password);

            if (typeof encrypted !== 'string' || typeof iv !== 'string') {
                throw new Error('Encryption output must be strings.');
            }

            // Ensure backend gets JSON-safe base64 text
            const b64 = /^[A-Za-z0-9+/]+={0,2}$/;
            if (!b64.test(encrypted) || !b64.test(iv)) {
                throw new Error('Ciphertext/IV are not base64.');
            }

            const payload = {
                site_name: siteName.trim(),
                site_username: username.trim(), // if backend expects json:"username", rename this key
                encrypted_password: encrypted,
                iv,
            };

            await axios.post(
                'http://localhost:8080/api/v1/vault',
                payload, // <-- do NOT JSON.stringify here
                {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'Content-Type': 'application/json',
                        Accept: 'application/json',
                    },
                }
            );

            setStatus('Secret saved successfully!');
            setSiteName('');
            setUsername('');
            setPassword('');
            onSecretAdded();
            setTimeout(() => setStatus(''), 3000);

        } catch (error: unknown) {
            console.error("Failed to save secret:", error);

            if (axios.isAxiosError(error)) {
                const apiError = (error.response?.data as { error?: string } | undefined)?.error;
                setStatus(apiError ? `Failed to save secret: ${apiError}` : 'Failed to save secret. Please try again.');
                return;
            }

            setStatus('Failed to save secret. Please try again.');
        }
    };

    return (
        <form onSubmit={handleSubmit} className="relative p-4 bg-slate-800 rounded-lg border border-slate-700 mb-6 flex flex-col sm:flex-row gap-4 items-center">
            <h3 className="text-lg font-semibold text-sky-400 mb-2 sm:mb-0 whitespace-nowrap">Add New Secret</h3>
            <div className="w-full flex flex-col sm:flex-row gap-4">
                <input
                    type="text"
                    placeholder="Site Name (e.g., Google)"
                    value={siteName}
                    onChange={(e) => setSiteName(e.target.value)}
                    className="p-2 rounded bg-slate-700 border border-slate-600 w-full flex-grow"
                    required
                />
                <input
                    type="text"
                    placeholder="Username / Email"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="p-2 rounded bg-slate-700 border border-slate-600 w-full flex-grow"
                    required
                />
                <input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="p-2 rounded bg-slate-700 border border-slate-600 w-full flex-grow"
                    required
                />
            </div>
            <button type="submit" className="bg-emerald-500 hover:bg-emerald-600 py-2 px-4 rounded font-bold w-full sm:w-auto transition-colors">
                Save
            </button>
            {status && <p className="text-xs mt-2 text-slate-400 absolute -bottom-5 right-5">{status}</p>}
        </form>
    );
}
