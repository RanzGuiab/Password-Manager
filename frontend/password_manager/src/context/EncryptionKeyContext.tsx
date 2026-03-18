// frontend/password_manager/src/context/EncryptionKeyContext.tsx
import { createContext, useContext, useState } from 'react';
import type { ReactNode } from 'react';

interface EncryptionKeyContextType {
    encryptionKey: CryptoKey | null;
    setEncryptionKey: (key: CryptoKey | null) => void;
}

const EncryptionKeyContext = createContext<EncryptionKeyContextType | undefined>(undefined);

export function EncryptionKeyProvider({ children }: { children: ReactNode }) {
    const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null);

    return (
        <EncryptionKeyContext.Provider value={{ encryptionKey, setEncryptionKey }}>
            {children}
        </EncryptionKeyContext.Provider>
    );
}

export function useEncryptionKey(): EncryptionKeyContextType {
    const context = useContext(EncryptionKeyContext);
    if (context === undefined) {
        throw new Error('useEncryptionKey must be used within an EncryptionKeyProvider');
    }
    return context;
}
