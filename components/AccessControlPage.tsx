

import React, { useState, useEffect, useRef } from 'react';
import { ShieldCheck, UserPlus, Upload, Trash2, X, CheckCircle, AlertTriangle } from 'lucide-react';

export const AccessControlPage: React.FC = () => {
  const [allowedUsers, setAllowedUsers] = useState<Array<{id: string, username: string, created_at: number}>>([]);
  const [newUser, setNewUser] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showNotification, setShowNotification] = useState<{type: 'success' | 'error', message: string} | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    setIsLoading(true);
    try {
        const res = await fetch('/api/allowed-users');
        if (res.ok) {
            const data = await res.json();
            setAllowedUsers(data);
        }
    } catch (e) {
        console.error("Failed to fetch allowed users", e);
    } finally {
        setIsLoading(false);
    }
  };

  const handleAddUser = async () => {
      if (!newUser.trim()) return;
      try {
          const res = await fetch('/api/allowed-users', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({ username: newUser })
          });
          if (res.ok) {
              await fetchUsers();
              setNewUser('');
              showToast('success', 'User added to allowlist');
          } else {
              showToast('error', 'Failed to add user (might already exist)');
          }
      } catch (e) {
          showToast('error', 'Network error');
      }
  };

  const handleDeleteUser = async (id: string, username: string) => {
      if (!confirm(`Remove ${username} from allowlist? They will no longer be able to onboard.`)) return;

      try {
          const res = await fetch(`/api/allowed-users?id=${id}`, {
              method: 'DELETE'
          });
          if (res.ok) {
              setAllowedUsers(prev => prev.filter(u => u.id !== id));
              showToast('success', `Removed ${username}`);
          } else {
              showToast('error', 'Failed to delete user');
          }
      } catch (e) {
          showToast('error', 'Network error');
      }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = async (evt) => {
          const text = evt.target?.result as string;
          // Split by newline or comma, remove empty/whitespace
          const names = text.split(/[\n,]+/).map(s => s.trim()).filter(s => s.length > 0);
          
          if (names.length === 0) {
              showToast('error', "No valid usernames found in file");
              return;
          }

          if (confirm(`Found ${names.length} usernames. Upload?`)) {
              try {
                  const res = await fetch('/api/allowed-users/bulk', {
                      method: 'POST',
                      headers: {'Content-Type': 'application/json'},
                      body: JSON.stringify({ usernames: names })
                  });
                  if (res.ok) {
                      const data = await res.json();
                      showToast('success', `Successfully added ${data.count} users`);
                      fetchUsers(); // Refresh list
                  }
              } catch (err) {
                  showToast('error', "Bulk upload failed");
              }
          }
      };
      reader.readAsText(file);
      // Reset input
      if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const showToast = (type: 'success' | 'error', message: string) => {
      setShowNotification({ type, message });
      setTimeout(() => setShowNotification(null), 3000);
  };

  return (
    <div className="space-y-6 relative">
      {/* Toast Notification */}
      {showNotification && (
        <div className={`p-4 rounded-lg flex items-center justify-between shadow-sm animate-in slide-in-from-top-2 duration-200 fixed top-6 right-6 z-50 max-w-sm ${
          showNotification.type === 'success' ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' : 'bg-rose-50 text-rose-800 border border-rose-200'
        }`}>
          <div className="flex items-center gap-2">
            {showNotification.type === 'success' ? <CheckCircle size={20} /> : <AlertTriangle size={20} />}
            <span className="font-medium text-sm">{showNotification.message}</span>
          </div>
          <button onClick={() => setShowNotification(null)} className="hover:opacity-75 ml-4">
            <X size={18} />
          </button>
        </div>
      )}

      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Access Control</h2>
          <p className="text-slate-500">Manage allowlist for client onboarding.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Actions */}
        <div className="space-y-6">
            
            {/* Add Single User */}
            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                <h3 className="font-semibold text-slate-700 mb-4 flex items-center gap-2">
                    <UserPlus size={18} /> Add Page Username
                </h3>
                <div className="space-y-3">
                    <label className="text-xs text-slate-500">Enter the exact Facebook Page username/ID</label>
                    <div className="flex gap-2">
                        <input 
                            type="text"
                            value={newUser}
                            onChange={(e) => setNewUser(e.target.value)}
                            placeholder="e.g. business_page_id"
                            className="flex-1 px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 min-w-0"
                        />
                        <button 
                            onClick={handleAddUser}
                            disabled={!newUser}
                            className="bg-blue-600 hover:bg-blue-700 text-white p-2 rounded-lg disabled:opacity-50 transition-colors flex-shrink-0"
                        >
                            <UserPlus size={18} />
                        </button>
                    </div>
                </div>
            </div>

            {/* Bulk Upload */}
            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                <h3 className="font-semibold text-slate-700 mb-4 flex items-center gap-2">
                    <Upload size={18} /> Bulk Import
                </h3>
                <div className="bg-slate-50 border border-slate-200 border-dashed rounded-lg p-6 text-center hover:bg-slate-100 transition-colors cursor-pointer" onClick={() => fileInputRef.current?.click()}>
                    <input 
                        type="file" 
                        ref={fileInputRef} 
                        className="hidden" 
                        accept=".csv,.txt"
                        onChange={handleFileUpload}
                    />
                    <div className="flex flex-col items-center gap-2 text-slate-500">
                        <Upload size={24} className="text-slate-400"/>
                        <span className="text-sm font-medium">Click to upload CSV</span>
                        <span className="text-xs text-slate-400">Comma separated usernames</span>
                    </div>
                </div>
            </div>
        </div>

        {/* Right Column: List */}
        <div className="lg:col-span-2 bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden flex flex-col h-[500px] lg:h-[600px]">
            <div className="p-4 border-b border-slate-200 bg-slate-50 flex justify-between items-center">
                <h3 className="font-semibold text-slate-700 flex items-center gap-2">
                    <ShieldCheck size={18} /> Allowed Users
                </h3>
                <span className="bg-white px-2 py-1 rounded-md text-xs border border-slate-200 font-mono text-slate-500">
                    Total: {allowedUsers.length}
                </span>
            </div>
            
            <div className="overflow-y-auto flex-1 p-0 custom-scrollbar">
                {isLoading ? (
                    <div className="flex items-center justify-center h-full text-slate-400">Loading...</div>
                ) : allowedUsers.length === 0 ? (
                     <div className="flex flex-col items-center justify-center h-full text-slate-400 p-8 text-center">
                        <ShieldCheck size={48} className="mb-4 opacity-20"/>
                        <p>No users in allowlist.</p>
                        <p className="text-sm">Add a username to grant onboarding access.</p>
                     </div>
                ) : (
                    <table className="w-full text-left text-sm">
                        <thead className="bg-slate-50 text-slate-500 font-medium border-b border-slate-200 sticky top-0">
                            <tr>
                                <th className="px-6 py-3">Username</th>
                                <th className="px-6 py-3 hidden sm:table-cell">Added Date</th>
                                <th className="px-6 py-3 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                            {allowedUsers.map(user => (
                                <tr key={user.id} className="hover:bg-slate-50 group">
                                    <td className="px-6 py-3 font-medium text-slate-800 font-mono break-all">{user.username}</td>
                                    <td className="px-6 py-3 text-slate-500 hidden sm:table-cell">{new Date(user.created_at).toLocaleDateString()}</td>
                                    <td className="px-6 py-3 text-right">
                                        <button 
                                            onClick={() => handleDeleteUser(user.id, user.username)}
                                            className="text-slate-400 hover:text-rose-600 transition-colors p-1 rounded hover:bg-rose-50"
                                            title="Remove access"
                                        >
                                            <Trash2 size={16} />
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>

      </div>
    </div>
  );
};