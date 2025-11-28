

import React, { useState, useEffect } from 'react';
import { PostCampaign, PostStatus, LogEntry } from '../types';
import { ChevronRight, FileText, CheckCircle2, AlertOctagon, Clock, X, Terminal, Image as ImageIcon } from 'lucide-react';

export const PostHistoryPage: React.FC = () => {
  const [posts, setPosts] = useState<PostCampaign[]>([]);
  const [selectedPost, setSelectedPost] = useState<PostCampaign | null>(null);
  const [modalView, setModalView] = useState<'details' | 'logs'>('details');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isLoadingLogs, setIsLoadingLogs] = useState(false);

  useEffect(() => {
    fetch('/api/posts')
        .then(res => res.json())
        .then(data => setPosts(data))
        .catch(console.error);
  }, []);

  const handleOpen = async (post: PostCampaign, view: 'details' | 'logs') => {
      setSelectedPost(post);
      setModalView(view);
      
      if (view === 'logs') {
          setIsLoadingLogs(true);
          try {
              const res = await fetch(`/api/logs?postId=${post.id}`);
              const data = await res.json();
              setLogs(data);
          } catch (e) {
              console.error("Failed to fetch logs", e);
          } finally {
              setIsLoadingLogs(false);
          }
      }
  };

  const handleTabChange = async (view: 'details' | 'logs') => {
      setModalView(view);
      if (view === 'logs' && selectedPost) {
           setIsLoadingLogs(true);
          try {
              const res = await fetch(`/api/logs?postId=${selectedPost.id}`);
              const data = await res.json();
              setLogs(data);
          } catch (e) {
              console.error("Failed to fetch logs", e);
          } finally {
              setIsLoadingLogs(false);
          }
      }
  };

  return (
    <div className="space-y-6 relative">
      <header>
        <h2 className="text-2xl font-bold text-slate-800">Campaign History</h2>
        <p className="text-slate-500">Monitor active broadcasts and view logs.</p>
      </header>

      {posts.length === 0 ? (
          <div className="bg-white p-12 text-center rounded-xl border border-slate-200 text-slate-500">
              No campaigns found. Create your first post to see history.
          </div>
      ) : (
          <div className="grid gap-6">
            {posts.map(post => (
              <div key={post.id} className="bg-white rounded-xl shadow-sm border border-slate-200 p-4 md:p-6 flex flex-col md:flex-row gap-6">
                
                {/* Thumbnail */}
                <div className="w-full md:w-32 h-48 md:h-32 bg-slate-100 rounded-lg overflow-hidden flex-shrink-0">
                  <img src={post.image_url} alt="Campaign" className="w-full h-full object-cover" />
                </div>

                {/* Info */}
                <div className="flex-1 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-2">
                    <div>
                      <h3 className="font-semibold text-slate-900 line-clamp-1">{post.base_caption}</h3>
                      <span className="text-xs text-slate-500 font-mono">ID: {post.id}</span>
                    </div>
                    <div className="self-start">
                      <StatusBadge status={post.status} />
                    </div>
                  </div>

                  {/* Progress Bar */}
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                        <span className="text-slate-600">Progress</span>
                        <span className="font-medium text-slate-900">
                          {post.total_accounts > 0 ? Math.round(((post.success_count + post.failure_count) / post.total_accounts) * 100) : 0}%
                        </span>
                    </div>
                    <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-blue-500 transition-all duration-500"
                          style={{ width: `${post.total_accounts > 0 ? ((post.success_count + post.failure_count) / post.total_accounts) * 100 : 0}%` }}
                        ></div>
                    </div>
                  </div>

                  {/* Stats */}
                  <div className="flex flex-wrap gap-4 md:gap-6 text-sm">
                    <div className="flex items-center gap-1.5 text-emerald-600">
                      <CheckCircle2 size={16} />
                      <span className="font-semibold">{post.success_count}</span> Posted
                    </div>
                    {post.failure_count > 0 && (
                      <div className="flex items-center gap-1.5 text-rose-600">
                        <AlertOctagon size={16} />
                        <span className="font-semibold">{post.failure_count}</span> Failed
                      </div>
                    )}
                    <div className="flex items-center gap-1.5 text-slate-400 ml-auto">
                      <Clock size={16} />
                      <span>{new Date(post.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex md:flex-col justify-center border-t md:border-t-0 md:border-l border-slate-100 pt-4 md:pt-0 md:pl-6 gap-2">
                  <button 
                    onClick={() => handleOpen(post, 'logs')}
                    className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-slate-50 hover:bg-slate-100 text-slate-700 font-medium rounded-lg text-sm transition-colors"
                  >
                    <FileText size={16} /> Logs
                  </button>
                  <button 
                    onClick={() => handleOpen(post, 'details')}
                    className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-blue-50 hover:bg-blue-100 text-blue-700 font-medium rounded-lg text-sm transition-colors"
                  >
                    Details <ChevronRight size={16} />
                  </button>
                </div>

              </div>
            ))}
          </div>
      )}

      {/* Details/Logs Modal */}
      {selectedPost && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-in fade-in duration-200">
           <div className="bg-white rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden animate-in zoom-in-95 duration-200">
              
              {/* Header */}
              <div className="px-4 py-3 md:px-6 md:py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50 flex-shrink-0">
                  <div className="flex gap-2 md:gap-4">
                      <button 
                        onClick={() => handleTabChange('details')}
                        className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${modalView === 'details' ? 'bg-white text-blue-600 shadow-sm ring-1 ring-slate-200' : 'text-slate-500 hover:text-slate-700'}`}
                      >
                        Details
                      </button>
                      <button 
                        onClick={() => handleTabChange('logs')}
                        className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${modalView === 'logs' ? 'bg-white text-blue-600 shadow-sm ring-1 ring-slate-200' : 'text-slate-500 hover:text-slate-700'}`}
                      >
                        Logs
                      </button>
                  </div>
                  <button onClick={() => setSelectedPost(null)} className="text-slate-400 hover:text-slate-600 transition-colors p-1">
                      <X size={20} />
                  </button>
              </div>

              {/* Content */}
              <div className="flex-1 overflow-y-auto p-4 md:p-6 bg-white">
                 {modalView === 'details' ? (
                     <div className="grid md:grid-cols-2 gap-6 md:gap-8">
                        <div>
                             <h4 className="font-semibold text-slate-900 mb-4 flex items-center gap-2"><ImageIcon size={18}/> Creative Asset</h4>
                             <img src={selectedPost.image_url} className="rounded-lg shadow-sm w-full border border-slate-200" alt="Creative"/>
                        </div>
                        <div className="space-y-6">
                            <div>
                                <h4 className="font-semibold text-slate-900 mb-2">Campaign Data</h4>
                                <div className="bg-slate-50 p-4 rounded-lg border border-slate-100 space-y-3 text-sm">
                                    <div className="flex justify-between"><span className="text-slate-500">ID</span> <span className="font-mono text-xs">{selectedPost.id}</span></div>
                                    <div className="flex justify-between"><span className="text-slate-500">Created</span> <span>{new Date(selectedPost.created_at).toLocaleString()}</span></div>
                                    <div className="flex justify-between"><span className="text-slate-500">Total Accounts</span> <span>{selectedPost.total_accounts}</span></div>
                                    <div className="flex justify-between"><span className="text-slate-500">Success Rate</span> <span className="text-emerald-600 font-bold">{selectedPost.total_accounts > 0 ? Math.round((selectedPost.success_count / selectedPost.total_accounts) * 100) : 0}%</span></div>
                                </div>
                            </div>
                            <div>
                                <h4 className="font-semibold text-slate-900 mb-2">Base Caption</h4>
                                <div className="bg-slate-50 p-4 rounded-lg border border-slate-100 text-sm text-slate-700 whitespace-pre-wrap max-h-40 overflow-y-auto">
                                    {selectedPost.base_caption}
                                </div>
                            </div>
                        </div>
                     </div>
                 ) : (
                     <div className="space-y-4">
                         <div className="flex items-center justify-between">
                            <h4 className="font-semibold text-slate-900 flex items-center gap-2"><Terminal size={18}/> Transmission Logs</h4>
                            <span className="text-xs text-slate-500">Showing recent entries</span>
                         </div>
                         <div className="border border-slate-200 rounded-lg overflow-x-auto">
                             <table className="w-full text-left text-sm whitespace-nowrap">
                                 <thead className="bg-slate-50 border-b border-slate-200 text-slate-500">
                                     <tr>
                                         <th className="px-4 py-3 font-medium">Timestamp</th>
                                         <th className="px-4 py-3 font-medium">Account</th>
                                         <th className="px-4 py-3 font-medium">Status</th>
                                         <th className="px-4 py-3 font-medium">Message</th>
                                     </tr>
                                 </thead>
                                 <tbody className="divide-y divide-slate-100">
                                     {isLoadingLogs ? (
                                         <tr><td colSpan={4} className="p-4 text-center text-slate-500">Loading logs...</td></tr>
                                     ) : logs.length === 0 ? (
                                         <tr><td colSpan={4} className="p-4 text-center text-slate-500">No logs available for this campaign yet.</td></tr>
                                     ) : (
                                        logs.map(log => (
                                            <tr key={log.id} className="hover:bg-slate-50">
                                                <td className="px-4 py-3 text-slate-500 font-mono text-xs">{new Date(log.timestamp).toLocaleTimeString()}</td>
                                                <td className="px-4 py-3 text-slate-900">{log.account_name}</td>
                                                <td className="px-4 py-3">
                                                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${log.status === 'success' ? 'bg-emerald-50 text-emerald-700' : 'bg-rose-50 text-rose-700'}`}>
                                                        {log.status === 'success' ? <CheckCircle2 size={12}/> : <AlertOctagon size={12}/>}
                                                        {log.status}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3 text-slate-600 font-mono text-xs truncate max-w-xs" title={log.message}>{log.message}</td>
                                            </tr>
                                        ))
                                     )}
                                 </tbody>
                             </table>
                         </div>
                     </div>
                 )}
              </div>
              
              {/* Footer */}
              <div className="px-4 py-3 md:px-6 md:py-4 border-t border-slate-100 bg-slate-50 flex justify-end flex-shrink-0">
                  <button onClick={() => setSelectedPost(null)} className="px-4 py-2 bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 rounded-lg text-sm font-medium transition-colors">
                      Close
                  </button>
              </div>
           </div>
        </div>
      )}
    </div>
  );
};

const StatusBadge: React.FC<{status: PostStatus}> = ({ status }) => {
  const styles = {
    [PostStatus.COMPLETED]: "bg-emerald-100 text-emerald-700",
    [PostStatus.FAILED]: "bg-rose-100 text-rose-700",
    [PostStatus.IN_PROGRESS]: "bg-blue-100 text-blue-700 animate-pulse",
    [PostStatus.PENDING]: "bg-slate-100 text-slate-700",
  };

  return (
    <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wide ${styles[status]}`}>
      {status.replace('_', ' ')}
    </span>
  );
};