// frontend/password_manager/src/components/SecretItem.tsx
import { useState } from 'react';

interface DecryptedSecret {
    id: number;
    site_name: string;
    site_username: string;
    password: string;
}

interface SecretItemProps {
    secret: DecryptedSecret;
    onDelete: (id: number) => void;
}

export default function SecretItem({ secret, onDelete }: SecretItemProps) {
    const [isPasswordVisible, setIsPasswordVisible] = useState(false);
    const [isCopied, setIsCopied] = useState(false);

    const handleCopy = () => {
        if (secret.password === "DECRYPTION FAILED") return;
        navigator.clipboard.writeText(secret.password);
        setIsCopied(true);
        setTimeout(() => setIsCopied(false), 2000); // Reset after 2 seconds
    };

    const isDecryptionFailed = secret.password === "DECRYPTION FAILED";

    return (
        <div className={`p-4 bg-slate-800 rounded-lg border ${isDecryptionFailed ? 'border-red-500/50' : 'border-slate-700'} flex flex-col sm:flex-row justify-between items-center transition-all duration-300`}>
            <div className="flex flex-col mb-3 sm:mb-0 text-center sm:text-left">
                <span className={`font-bold text-lg ${isDecryptionFailed ? 'text-red-400' : 'text-emerald-400'}`}>{secret.site_name}</span>
                <span className="text-slate-400 text-sm">{secret.site_username}</span>
            </div>
            <div className="flex gap-2 items-center">
                <input
                    type={isPasswordVisible ? 'text' : 'password'}
                    value={secret.password}
                    readOnly
                    className={`bg-slate-700 p-2 rounded text-sm w-40 border font-mono ${isDecryptionFailed ? 'border-red-500/50 text-red-400' : 'border-slate-600'}`}
                />
                <button
                    onClick={() => setIsPasswordVisible(!isPasswordVisible)}
                    className="p-2 rounded text-slate-400 hover:bg-slate-700 hover:text-white transition-colors disabled:opacity-50"
                    aria-label={isPasswordVisible ? 'Hide password' : 'Show password'}
                    disabled={isDecryptionFailed}
                >
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        {isPasswordVisible ? (
                            <path strokeLinecap="round" strokeLinejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242" />
                        ) : (
                            <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        )}
                    </svg>
                </button>
                <button
                    onClick={handleCopy}
                    className="bg-sky-600 px-3 py-2 rounded text-xs font-semibold hover:bg-sky-500 transition-colors w-24 text-center disabled:bg-slate-600 disabled:cursor-not-allowed"
                    disabled={isDecryptionFailed}
                >
                    {isCopied ? 'Copied!' : 'Copy'}
                </button>
                <button
                    onClick={() => onDelete(secret.id)}
                    className="bg-red-700 px-3 py-2 rounded text-xs font-semibold hover:bg-red-600 transition-colors"
                >
                    Delete
                </button>
            </div>
        </div>
    );
}
