
import React, { useState } from 'react';
import { Lock, User, Loader2, AlertCircle } from 'lucide-react';

interface LoginPageProps {
  onLogin: (token: string) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    // Setup timeout to prevent hanging
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); // 8 second timeout

    try {
      // In a real app, this URL should be your actual worker URL
      // If you are developing locally, ensure your proxy is set up or use the full URL
      const response = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);

      // Check if response is actually JSON (handles 404/500 HTML pages from proxies)
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        throw new Error(`Server returned unexpected format: ${response.status}`);
      }

      const data = await response.json();

      if (response.ok && data.success) {
        onLogin(data.token);
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (err: any) {
      console.error("Login Error:", err);
      if (err.name === 'AbortError') {
        setError('Server timed out. Please check your connection.');
      } else {
        setError(err.message || 'Connection error. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-xl w-full max-w-md overflow-hidden flex flex-col min-h-[550px]">
        <div className="bg-slate-900 p-8 text-center">
          <div className="mx-auto w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center mb-4 shadow-lg shadow-blue-900/50">
            <Lock className="text-white" size={24} />
          </div>
          <h1 className="text-2xl font-bold text-white">SocialSync Admin</h1>
          <p className="text-slate-400 text-sm mt-1">Please sign in to continue</p>
        </div>

        <div className="p-8 flex-1 flex flex-col justify-center">
          {error && (
            <div className="mb-6 p-3 bg-rose-50 border border-rose-200 text-rose-700 rounded-lg text-sm flex items-center gap-2">
              <AlertCircle size={16} />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">Username</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                  <User size={18} />
                </div>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                  placeholder="admin"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">Password</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                  <Lock size={18} />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2.5 px-4 rounded-lg shadow-lg shadow-blue-900/10 transition-all flex items-center justify-center gap-2 disabled:opacity-70 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <>
                  <Loader2 size={18} className="animate-spin" /> Signing in...
                </>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          <p className="text-center text-xs text-slate-400 mt-6">
            Default credentials for first run: <span className="font-mono text-slate-500">admin / password</span>
          </p>
        </div>

        {/* Footer */}
        <div className="bg-slate-50 p-4 border-t border-slate-100">
           <div className="flex flex-wrap justify-center gap-4 text-xs text-slate-400">
             <a href="#privacy" className="hover:text-slate-600 hover:underline">Privacy Policy</a>
             <span>|</span>
             <a href="#terms" className="hover:text-slate-600 hover:underline">Terms of Service</a>
             <span>|</span>
             <a href="#data_deletion" className="hover:text-slate-600 hover:underline">Data Deletion</a>
           </div>
        </div>
      </div>
    </div>
  );
};
