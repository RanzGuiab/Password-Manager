import { useEffect, useState, useCallback } from 'react';
import axios from 'axios';
import AddSecretForm from './AddSecretForm';
import SecretItem from './SecretItem';
import { decrypt } from '../utils/crypto';
import { useEncryptionKey } from '../context/EncryptionKeyContext';

// ... (interface definitions remain the same)
interface RawSecret {
    id: number;
    encrypted_site_name?: string;
    site_name_iv?: string;
    encrypted_site_username?: string;
    site_username_iv?: string;
    encrypted_password: string;
    iv: string;
    enc_version?: string;

    // Legacy fallback fields (old rows)
    site_name?: string;
    site_username?: string;
}
interface DecryptedSecret {
    id: number;
    site_name: string;
    site_username: string;
    password: string;
}


type VaultProps = {
  onLogout: () => void;
};

export default function Vault({ onLogout }: VaultProps) {
  const { encryptionKey } = useEncryptionKey(); // Use context
  const [secrets, setSecrets] = useState<RawSecret[]>([]);
  const [decryptedSecrets, setDecryptedSecrets] = useState<DecryptedSecret[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const token = localStorage.getItem('vault_token');

  const fetchSecrets = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await axios.get('http://localhost:8080/api/v1/vault', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSecrets(res.data || []);
    } catch (error) {
      console.error("Failed to fetch secrets", error);
      setSecrets([]);
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (token && encryptionKey) {
      fetchSecrets();
    }
  }, [token, encryptionKey, fetchSecrets]);

  const decryptField = useCallback(
    async (ciphertext?: string, iv?: string): Promise<string | null> => {
      if (!encryptionKey || !ciphertext || !iv) return null;
      try {
        return await decrypt(encryptionKey, ciphertext, iv);
      } catch {
        return null;
      }
    },
    [encryptionKey]
  );

  useEffect(() => {
    let active = true;

    const decryptAll = async () => {
      if (!encryptionKey) {
        setDecryptedSecrets([]);
        setIsLoading(false);
        return;
      }

      const output = await Promise.all(
        secrets.map(async (secret): Promise<DecryptedSecret> => {
          const [siteName, siteUsername, password] = await Promise.all([
            decryptField(secret.encrypted_site_name, secret.site_name_iv),
            decryptField(secret.encrypted_site_username, secret.site_username_iv),
            decryptField(secret.encrypted_password, secret.iv),
          ]);

          return {
            id: secret.id,
            site_name: siteName ?? secret.site_name ?? 'DECRYPTION FAILED',
            site_username: siteUsername ?? secret.site_username ?? 'DECRYPTION FAILED',
            password: password ?? 'DECRYPTION FAILED',
          };
        })
      );

      if (active) {
        setDecryptedSecrets(output);
        setIsLoading(false);
      }
    };

    void decryptAll();
    return () => {
      active = false;
    };
  }, [secrets, encryptionKey, decryptField]);

  const handleDelete = async (id: number) => {
    if (window.confirm("Are you sure you want to permanently delete this secret?")) {
        try {
            await axios.delete(`http://localhost:8080/api/v1/vault/${id}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            fetchSecrets();
        } catch (error) {
            console.error("Failed to delete secret:", error);
            alert("Failed to delete secret. Please try again.");
        }
    }
  };

  // If key is missing, something is wrong. Don't render the vault.
  if (!encryptionKey) {
      return (
          <div className="p-6 text-center">
              <h2 className="text-xl text-red-500">Encryption Key Missing!</h2>
              <p className="text-slate-400">Cannot display vault. Please log out and log back in.</p>
              <button onClick={onLogout} className="mt-4 bg-sky-500 px-4 py-2 rounded">Logout</button>
          </div>
      )
  }

  return (
    <div className="p-4 sm:p-6 bg-slate-900 rounded-xl border border-slate-700 w-full max-w-4xl animate-fade-in">
      <div className="mb-6 flex items-center justify-between">
        <h2 className="text-xl sm:text-2xl font-bold text-sky-400">Your Secure Vault</h2>
        <button
          onClick={onLogout}
          className="bg-red-600 px-3 py-1.5 rounded text-sm font-semibold hover:bg-red-500 transition-colors"
        >
          Logout
        </button>
      </div>
      
      <AddSecretForm onSecretAdded={fetchSecrets} />

      <div className="mt-8">
        {isLoading ? (
            <div className="text-center text-slate-400">Loading and decrypting secrets...</div>
        ) : decryptedSecrets.length === 0 ? (
            <div className="text-center bg-slate-800 p-8 rounded-lg border border-slate-700">
                <h3 className="text-xl font-semibold text-white">Your Vault is Empty</h3>
                <p className="text-slate-400 mt-2">Use the form above to add your first secret.</p>
            </div>
        ) : (
            <div className="grid gap-4">
                {decryptedSecrets.map((secret) => (
                    <SecretItem
                        key={secret.id}
                        secret={secret}
                        onDelete={handleDelete}
                    />
                ))}
            </div>
        )}
      </div>
    </div>
  );
}