

import React, { useState, useEffect } from 'react';
import { Facebook, Search, RefreshCw, AlertTriangle, CheckCircle, X, Trash2, ExternalLink, Link as LinkIcon } from 'lucide-react';
import { SocialAccount, AccountStatus } from '../types';

export const AccountsPage: React.FC = () => {
  const [accounts, setAccounts] = useState<SocialAccount[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [showNotification, setShowNotification] = useState<{type: 'success' | 'error', message: string} | null>(null);
  const [selectedAccount, setSelectedAccount] = useState<SocialAccount | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const fetchAccounts = async () => {
      setIsLoading(true);
      try {
          const res = await fetch('/api/accounts');
          if (res.ok) {
              const data = await res.json();
              setAccounts(data);
          }
      } catch (e) {
          console.error("Failed to load accounts", e);
      } finally {
          setIsLoading(false);
      }
  };

  useEffect(() => {
    fetchAccounts();

    // Check for success/error params from OAuth callback
    const hashParts = window.location.hash.split('?');
    
    if (hashParts.length > 1) {
      const params = new URLSearchParams(hashParts[1]);
      
      if (params.get('success') === 'true') {
        const count = params.get('count') || '0';
        setShowNotification({
          type: 'success',
          message: `Successfully connected ${count} accounts from Facebook!`
        });
        fetchAccounts(); // Refresh list after connection
      } else if (params.get('error')) {
        const errorCode = params.get('error');
        const errorDesc = params.get('error_description');
        let message = 'Connection Failed: An unknown error occurred.';
        
        if (errorCode === 'access_denied') {
          message = 'Connection Failed: User denied permissions.';
        } else if (errorDesc) {
          message = `Connection Failed: ${errorDesc}`;
        } else if (errorCode) {
          message = `Connection Failed: ${errorCode}`;
        }

        setShowNotification({
          type: 'error',
          message: message
        });
      }
      const cleanHash = hashParts[0];
      window.history.replaceState(null, '', window.location.pathname + cleanHash);
    }
  }, []);

  const handleConnect = () => {
    // Open in new tab to avoid X-Frame-Options (Refused to connect) errors in iframes
    const width = 600;
    const height = 700;
    const left = window.screen.width / 2 - width / 2;
    const top = window.screen.height / 2 - height / 2;
    
    window.open(
      '/api/auth/login?source=admin', 
      'SocialSyncLogin', 
      `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes,status=yes`
    );
  };
  
  const handleCopyInviteLink = () => {
    const inviteUrl = `${window.location.origin}/#onboarding`;
    navigator.clipboard.writeText(inviteUrl);
    setShowNotification({ type: 'success', message: 'Invite link copied to clipboard!' });
    setTimeout(() => {
        setShowNotification(null);
    }, 3000);
  };

  const handleDisconnect = (account: SocialAccount) => {
    if (confirm(`Are you sure you want to disconnect ${account.fb_page_name}? This will stop all future broadcasts to this account.`)) {
        // In a real app, send DELETE request to API
        // For now, assume success
        setShowNotification({ type: 'success', message: `Disconnected ${account.fb_page_name}` });
        setSelectedAccount(null);
    }
  };

  const filteredAccounts = accounts.filter(acc => 
    acc.fb_page_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    acc.ig_username.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 relative">
      {showNotification && (
        <div className={`p-4 rounded-lg flex items-center justify-between shadow-sm animate-in slide-in-from-top-2 duration-200 fixed top-20 right-4 left-4 md:left-auto md:top-6 md:right-6 z-50 max-w-sm ${
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

      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Connected Accounts</h2>
          <p className="text-slate-500">Manage connected Facebook Pages and Instagram accounts.</p>
        </div>
        
        <div className="flex flex-col sm:flex-row gap-3">
             <button 
              onClick={handleCopyInviteLink}
              className="flex items-center justify-center gap-2 bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 font-medium py-2 px-4 rounded-lg transition-colors shadow-sm"
              title="Copy link to send to clients for self-service connection"
            >
              <LinkIcon size={18} />
              Copy Invite Link
            </button>
            <button 
              onClick={handleConnect}
              className="flex items-center justify-center gap-2 bg-[#1877F2] hover:bg-[#166fe5] text-white font-medium py-2 px-4 rounded-lg transition-colors shadow-sm"
            >
              <Facebook size={20} />
              Connect Manually
            </button>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
        {/* Filters */}
        <div className="p-4 border-b border-slate-200 flex flex-col sm:flex-row items-center gap-4">
          <div className="relative flex-1 w-full max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
            <input 
              type="text" 
              placeholder="Search pages or usernames..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
            />
          </div>
          <button 
            onClick={fetchAccounts}
            className="text-slate-500 hover:text-blue-600 transition-colors self-end sm:self-auto"
            title="Refresh List"
          >
            <RefreshCw size={18} className={isLoading ? 'animate-spin' : ''} />
          </button>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm whitespace-nowrap">
            <thead className="bg-slate-50 text-slate-500 font-medium border-b border-slate-200">
              <tr>
                <th className="px-6 py-3">Owner / Location</th>
                <th className="px-6 py-3">Page Name</th>
                <th className="px-6 py-3">Instagram Handle</th>
                <th className="px-6 py-3">Status</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredAccounts.length > 0 ? (
                filteredAccounts.map((account) => (
                    <tr key={account.id} className="hover:bg-slate-50 transition-colors">
                    <td className="px-6 py-4 font-medium text-slate-900">{account.owner_name}</td>
                    <td className="px-6 py-4 text-slate-600">{account.fb_page_name}</td>
                    <td className="px-6 py-4 text-slate-600">@{account.ig_username}</td>
                    <td className="px-6 py-4">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                        account.status === AccountStatus.ACTIVE 
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : account.status === AccountStatus.DISCONNECTED
                            ? 'bg-slate-100 text-slate-700 border-slate-200'
                            : 'bg-rose-50 text-rose-700 border-rose-200'
                        }`}>
                        {account.status === AccountStatus.ACTIVE && <CheckCircle size={12} />}
                        {account.status === AccountStatus.DISCONNECTED && <AlertTriangle size={12} />}
                        {account.status === AccountStatus.ERROR && <AlertTriangle size={12} />}
                        {account.status.charAt(0).toUpperCase() + account.status.slice(1)}
                        </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                        <button 
                            onClick={() => setSelectedAccount(account)}
                            className="text-blue-600 hover:text-blue-800 font-medium text-xs hover:underline"
                        >
                            Manage
                        </button>
                    </td>
                    </tr>
                ))
              ) : (
                <tr>
                    <td colSpan={5} className="px-6 py-8 text-center text-slate-400">
                        {isLoading ? 'Loading accounts...' : 'No accounts connected yet.'}
                    </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        
        <div className="p-4 border-t border-slate-200 text-xs text-slate-500 flex flex-col sm:flex-row justify-between gap-2">
          <span>Showing {filteredAccounts.length} of {accounts.length} accounts</span>
          <span>Last synced: {new Date().toLocaleTimeString()}</span>
        </div>
      </div>

      {/* Account Details Modal */}
      {selectedAccount && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-in fade-in duration-200">
            <div className="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden animate-in zoom-in-95 duration-200">
                <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50">
                    <h3 className="font-bold text-slate-800">Manage Account</h3>
                    <button onClick={() => setSelectedAccount(null)} className="text-slate-400 hover:text-slate-600 transition-colors">
                        <X size={20} />
                    </button>
                </div>
                
                <div className="p-6 space-y-6">
                    <div className="flex items-center gap-4">
                        <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-full flex items-center justify-center text-white font-bold text-2xl shadow-lg shadow-blue-500/30 flex-shrink-0">
                            {selectedAccount.fb_page_name.charAt(0)}
                        </div>
                        <div className="min-w-0">
                            <h4 className="font-bold text-lg text-slate-900 leading-tight truncate">{selectedAccount.fb_page_name}</h4>
                            <div className="flex items-center gap-1 text-slate-500 text-sm">
                                <ExternalLink size={12} />
                                <span className="truncate">@{selectedAccount.ig_username}</span>
                            </div>
                        </div>
                    </div>

                    <div className="space-y-3 bg-slate-50 p-4 rounded-lg border border-slate-100">
                        <div className="flex justify-between text-sm">
                            <span className="text-slate-500">Owner</span>
                            <span className="font-medium text-slate-900 truncate ml-2">{selectedAccount.owner_name}</span>
                        </div>
                        <div className="flex justify-between text-sm">
                            <span className="text-slate-500">Status</span>
                            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                                selectedAccount.status === AccountStatus.ACTIVE ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-200 text-slate-700'
                            }`}>
                                {selectedAccount.status.toUpperCase()}
                            </span>
                        </div>
                         <div className="flex justify-between text-sm">
                            <span className="text-slate-500">Last Synced</span>
                            <span className="font-medium text-slate-900">{new Date(selectedAccount.last_updated).toLocaleDateString()}</span>
                        </div>
                        <div className="flex justify-between text-sm">
                            <span className="text-slate-500">Internal ID</span>
                            <span className="font-mono text-xs text-slate-400 bg-white px-1.5 py-0.5 rounded border border-slate-200 truncate ml-2 max-w-[150px]">{selectedAccount.id}</span>
                        </div>
                    </div>
                </div>

                <div className="px-6 py-4 bg-slate-50 border-t border-slate-100 flex gap-3">
                    <button 
                        onClick={() => handleDisconnect(selectedAccount)}
                        className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-white border border-rose-200 text-rose-600 hover:bg-rose-50 rounded-lg text-sm font-medium transition-colors hover:border-rose-300"
                    >
                        <Trash2 size={16} /> Disconnect
                    </button>
                    <button 
                         onClick={() => setSelectedAccount(null)}
                         className="flex-1 px-4 py-2.5 bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 rounded-lg text-sm font-medium transition-colors"
                    >
                        Close
                    </button>
                </div>
            </div>
        </div>
      )}
    </div>
  );
};