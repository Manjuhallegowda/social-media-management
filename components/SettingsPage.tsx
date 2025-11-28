import React, { useEffect, useState } from 'react';
import {
  Server,
  Database,
  Cloud,
  ShieldCheck,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
} from 'lucide-react';
import { API_URL } from '../services/config';

interface SystemStatus {
  database: { status: string; message: string };
  storage: { status: string; message: string };
  meta: { status: string; message: string; appId: string };
  env: Record<string, boolean>;
}

export const SettingsPage: React.FC = () => {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = () => {
    setLoading(true);
    setError(null);
    fetch(`${API_URL}/system-status`)
      .then((res) => {
        if (!res.ok) throw new Error('Failed to fetch status');
        return res.json();
      })
      .then((data) => setStatus(data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const getStatusColor = (s: string) => {
    if (s === 'connected' || s === 'configured') return 'text-emerald-500';
    if (s === 'unknown') return 'text-slate-400';
    return 'text-rose-500';
  };

  const getStatusIcon = (s: string) => {
    if (s === 'connected' || s === 'configured')
      return <CheckCircle size={16} className="text-emerald-500" />;
    return <AlertTriangle size={16} className="text-rose-500" />;
  };

  return (
    <div className="space-y-6">
      <header className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">Settings</h2>
          <p className="text-slate-500">
            System configuration and real-time environment status.
          </p>
        </div>
        <button
          onClick={fetchStatus}
          className="p-2 text-slate-500 hover:text-blue-600 hover:bg-slate-100 rounded-lg transition-colors"
          title="Refresh Status"
        >
          <RefreshCw size={20} className={loading ? 'animate-spin' : ''} />
        </button>
      </header>

      {error && (
        <div className="bg-rose-50 border border-rose-200 text-rose-700 p-4 rounded-xl flex items-center gap-2">
          <AlertTriangle size={20} />
          <span>Could not connect to backend: {error}</span>
        </div>
      )}

      {status ? (
        <div className="grid gap-6">
          {/* System Status Card */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
            <h3 className="text-lg font-semibold text-slate-800 mb-4 flex items-center gap-2">
              <Server size={20} className="text-blue-500" />
              System Components
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Database */}
              <div
                className={`p-4 rounded-lg border flex items-start gap-3 ${
                  status.database.status === 'connected'
                    ? 'bg-slate-50 border-slate-100'
                    : 'bg-rose-50 border-rose-200'
                }`}
              >
                <Database
                  className={getStatusColor(status.database.status)}
                  size={20}
                />
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium text-slate-900">
                      Cloudflare D1 Database
                    </p>
                    {getStatusIcon(status.database.status)}
                  </div>
                  <p className="text-xs text-slate-500 mt-1">
                    {status.database.message || 'Checking...'}
                  </p>
                </div>
              </div>

              {/* Storage */}
              <div
                className={`p-4 rounded-lg border flex items-start gap-3 ${
                  status.storage.status === 'connected'
                    ? 'bg-slate-50 border-slate-100'
                    : 'bg-rose-50 border-rose-200'
                }`}
              >
                <Cloud
                  className={getStatusColor(status.storage.status)}
                  size={20}
                />
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium text-slate-900">
                      Cloudflare R2 Storage
                    </p>
                    {getStatusIcon(status.storage.status)}
                  </div>
                  <p className="text-xs text-slate-500 mt-1">
                    {status.storage.message || 'Checking...'}
                  </p>
                </div>
              </div>

              {/* Meta API */}
              <div
                className={`p-4 rounded-lg border flex items-start gap-3 ${
                  status.meta.status === 'configured'
                    ? 'bg-slate-50 border-slate-100'
                    : 'bg-rose-50 border-rose-200'
                }`}
              >
                <ShieldCheck
                  className={getStatusColor(status.meta.status)}
                  size={20}
                />
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium text-slate-900">Meta Graph API</p>
                    {getStatusIcon(status.meta.status)}
                  </div>
                  <p className="text-xs text-slate-500 mt-1">
                    Status: {status.meta.status.toUpperCase()}
                  </p>
                  <p className="text-xs text-slate-500">
                    App ID: {status.meta.appId}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Configuration Info */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
            <h3 className="text-lg font-semibold text-slate-800 mb-4">
              Environment Configuration
            </h3>
            <p className="text-sm text-slate-600 mb-4">
              Verification of server-side environment variables required for
              operation.
            </p>

            <div className="overflow-hidden rounded-lg border border-slate-200">
              <table className="min-w-full divide-y divide-slate-200 bg-slate-50">
                <thead className="bg-slate-100">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Variable
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {Object.entries(status.env).map(([key, isSet]) => (
                    <tr key={key}>
                      <td className="px-6 py-3 text-sm font-mono text-slate-600">
                        {key}
                      </td>
                      <td className="px-6 py-3 text-sm font-medium flex items-center gap-1">
                        {isSet ? (
                          <>
                            <CheckCircle
                              size={14}
                              className="text-emerald-500"
                            />
                            <span className="text-emerald-600">Set</span>
                          </>
                        ) : (
                          <>
                            <AlertTriangle
                              size={14}
                              className="text-rose-500"
                            />
                            <span className="text-rose-600">Missing</span>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-white p-12 text-center rounded-xl border border-slate-200 text-slate-500">
          {loading ? 'Checking system status...' : 'System status unavailable.'}
        </div>
      )}
    </div>
  );
};
