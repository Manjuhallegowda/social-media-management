import React, { useEffect, useState } from 'react';
import {
  Server,
  Database,
  Cloud,
  ShieldCheck,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  UserPlus,
  Trash2,
  Users,
  Key,
  X,
} from 'lucide-react';
import { apiFetch } from '../services/config';

interface SystemStatus {
  database: { status: string; message: string };
  storage: { status: string; message: string };
  meta: { status: string; message: string; appId: string };
  env: Record<string, boolean>;
}

interface AdminUser {
  id: string;
  username: string;
  is_active: number;
  created_at: number;
  last_login: number | null;
}

export const SettingsPage: React.FC = () => {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Admin management state
  const [showAddModal, setShowAddModal] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [notification, setNotification] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);

  const fetchStatus = () => {
    setLoading(true);
    setError(null);
    apiFetch(`/system-status`)
      .then((res) => {
        if (!res.ok) throw new Error('Failed to fetch status');
        return res.json();
      })
      .then((data) => setStatus(data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  const fetchAdminUsers = () => {
    apiFetch(`/admin/users`)
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data)) {
          setAdminUsers(data);
        }
      })
      .catch((err) => console.error('Failed to fetch admin users:', err));
  };

  useEffect(() => {
    fetchStatus();
    fetchAdminUsers();
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

  const handleAddAdmin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    try {
      const res = await apiFetch(`/admin/users`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: newUsername, password: newPassword }),
      });

      const data = await res.json();

      if (res.ok && data.success) {
        setShowAddModal(false);
        setNewUsername('');
        setNewPassword('');
        fetchAdminUsers();
        showNotification('success', 'Admin user created successfully');
      } else {
        showNotification('error', data.error || 'Failed to create admin');
      }
    } catch (err) {
      showNotification('error', 'Network error');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteAdmin = async (id: string) => {
    if (!confirm('Are you sure you want to delete this admin user?')) return;

    try {
      const res = await apiFetch(`/admin/users?id=${id}`, {
        method: 'DELETE',
      });

      const data = await res.json();

      if (res.ok && data.success) {
        fetchAdminUsers();
        showNotification('success', 'Admin user deleted');
      } else {
        showNotification('error', data.error || 'Failed to delete admin');
      }
    } catch (err) {
      showNotification('error', 'Network error');
    }
  };

  const handleToggleActive = async (id: string) => {
    try {
      const res = await apiFetch(`/admin/users/toggle`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      });

      const data = await res.json();

      if (res.ok && data.success) {
        fetchAdminUsers();
        showNotification(
          'success',
          `Admin ${data.is_active ? 'activated' : 'deactivated'}`
        );
      } else {
        showNotification('error', data.error || 'Failed to update admin');
      }
    } catch (err) {
      showNotification('error', 'Network error');
    }
  };

  const showNotification = (type: 'success' | 'error', message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 3000);
  };

  return (
    <div className="space-y-6 relative">
      {/* Toast Notification */}
      {notification && (
        <div
          className={`p-4 rounded-lg flex items-center justify-between shadow-sm animate-in slide-in-from-top-2 duration-200 fixed top-6 right-6 z-50 max-w-sm ${
            notification.type === 'success'
              ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
              : 'bg-rose-50 text-rose-800 border border-rose-200'
          }`}
        >
          <div className="flex items-center gap-2">
            {notification.type === 'success' ? (
              <CheckCircle size={20} />
            ) : (
              <AlertTriangle size={20} />
            )}
            <span className="font-medium text-sm">{notification.message}</span>
          </div>
          <button
            onClick={() => setNotification(null)}
            className="hover:opacity-75 ml-4"
          >
            <X size={18} />
          </button>
        </div>
      )}

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

          {/* Admin Users Management */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold text-slate-800 flex items-center gap-2">
                <Users size={20} className="text-blue-500" />
                Admin Users
              </h3>
              <button
                onClick={() => setShowAddModal(true)}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors"
              >
                <UserPlus size={16} />
                Add Admin
              </button>
            </div>

            <div className="overflow-hidden rounded-lg border border-slate-200">
              <table className="min-w-full divide-y divide-slate-200 bg-slate-50">
                <thead className="bg-slate-100">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Username
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Created
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Last Login
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-slate-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {adminUsers.map((user) => (
                    <tr key={user.id}>
                      <td className="px-6 py-3 text-sm font-medium text-slate-800">
                        {user.username}
                      </td>
                      <td className="px-6 py-3 text-sm">
                        <span
                          className={`px-2 py-1 rounded-full text-xs font-medium ${
                            user.is_active
                              ? 'bg-emerald-100 text-emerald-700'
                              : 'bg-slate-100 text-slate-600'
                          }`}
                        >
                          {user.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-sm text-slate-500">
                        {new Date(user.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-3 text-sm text-slate-500">
                        {user.last_login
                          ? new Date(user.last_login).toLocaleString()
                          : 'Never'}
                      </td>
                      <td className="px-6 py-3 text-sm text-right">
                        <div className="flex justify-end gap-2">
                          <button
                            onClick={() => handleToggleActive(user.id)}
                            className="p-1.5 text-slate-500 hover:text-blue-600 hover:bg-blue-50 rounded transition-colors"
                            title={user.is_active ? 'Deactivate' : 'Activate'}
                          >
                            <Key size={16} />
                          </button>
                          <button
                            onClick={() => handleDeleteAdmin(user.id)}
                            className="p-1.5 text-slate-500 hover:text-rose-600 hover:bg-rose-50 rounded transition-colors"
                            title="Delete admin"
                          >
                            <Trash2 size={16} />
                          </button>
                        </div>
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

      {/* Add Admin Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-slate-900/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl max-w-md w-full p-6">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold text-slate-800">
                Add New Admin
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-slate-600"
              >
                <X size={20} />
              </button>
            </div>

            <form onSubmit={handleAddAdmin} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">
                  Username
                </label>
                <input
                  type="text"
                  required
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                  placeholder="Enter username"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">
                  Password
                </label>
                <input
                  type="password"
                  required
                  minLength={6}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
                  placeholder="Min 6 characters"
                />
              </div>

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="flex-1 px-4 py-2 border border-slate-200 text-slate-600 rounded-lg hover:bg-slate-50 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
                >
                  {isSubmitting ? 'Creating...' : 'Create Admin'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
