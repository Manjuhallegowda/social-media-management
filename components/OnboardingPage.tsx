
import React, { useState, useEffect } from 'react';
import { Facebook, CheckCircle, AlertTriangle, ShieldCheck, ArrowRight, Lock, Loader2 } from 'lucide-react';

export const OnboardingPage: React.FC = () => {
  const [step, setStep] = useState<'verify' | 'connect'>('verify');
  const [username, setUsername] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  
  const [status, setStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');

  useEffect(() => {
    // Check for success/error params from OAuth callback
    const hashParts = window.location.hash.split('?');
    
    if (hashParts.length > 1) {
      const params = new URLSearchParams(hashParts[1]);
      
      if (params.get('success') === 'true') {
        const count = params.get('count') || '0';
        setStep('connect');
        setStatus('success');
        setMessage(`Successfully connected ${count} accounts! You can now close this window.`);
      } else if (params.get('error')) {
        setStep('connect');
        setStatus('error');
        setMessage('Connection failed. Please try again or contact support.');
      }
      
      // Clean up URL to prevent re-triggering on refresh
      window.history.replaceState(null, '', window.location.pathname + '#onboarding');
    }
  }, []);

  const handleVerify = async () => {
      if (!username.trim()) return;
      setIsVerifying(true);
      
      try {
          const res = await fetch('/api/verify-user', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({ username: username.trim() })
          });
          
          if (res.ok) {
              const data = await res.json();
              if (data.verified) {
                  setStep('connect');
              } else {
                  alert("Access Denied: This Page Username is not in our allowlist. Please contact the administrator.");
              }
          } else {
              // Fallback for demo if backend is offline/mocked poorly
              // In real prod, this block handles server errors
              alert("Verification service unavailable. Please try again.");
          }
      } catch (e) {
          console.error("Verify failed", e);
          alert("Connection error occurred.");
      } finally {
          setIsVerifying(false);
      }
  };

  const handleConnect = () => {
    // Open in new tab to avoid X-Frame-Options errors
    const width = 600;
    const height = 700;
    const left = window.screen.width / 2 - width / 2;
    const top = window.screen.height / 2 - height / 2;
    
    // Send 'source=onboarding' to tell the backend to redirect back here
    window.open(
      '/api/auth/login?source=onboarding', 
      'SocialSyncConnect', 
      `width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes,status=yes`
    );
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col items-center justify-center p-6">
      <div className="max-w-md w-full bg-white rounded-2xl shadow-xl overflow-hidden border border-slate-100 flex flex-col min-h-[500px]">
        
        {/* Header */}
        <div className="bg-slate-900 p-8 text-center">
          <div className="mx-auto w-16 h-16 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center mb-4 shadow-lg shadow-blue-500/30">
            <ShieldCheck className="text-white" size={32} />
          </div>
          <h1 className="text-2xl font-bold text-white">SocialSync Onboarding</h1>
          <p className="text-slate-400 mt-2 text-sm">
             {step === 'verify' ? 'Secure Identity Verification' : 'Connect Your Accounts'}
          </p>
        </div>

        {/* Content */}
        <div className="p-8 flex-1 flex flex-col justify-center">
          
          {step === 'verify' && (
              <div className="space-y-6 animate-in slide-in-from-right-4 duration-300">
                  <div className="text-center">
                      <h3 className="font-semibold text-slate-800">Verify Identity</h3>
                      <p className="text-sm text-slate-500 mt-1">Please enter your assigned Page Username to proceed.</p>
                  </div>
                  
                  <div className="space-y-3">
                      <div className="relative">
                          <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                          <input 
                              type="text"
                              value={username}
                              onChange={(e) => setUsername(e.target.value)}
                              className="w-full pl-10 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                              placeholder="e.g. business_page_name"
                          />
                      </div>
                      <button 
                          onClick={handleVerify}
                          disabled={!username || isVerifying}
                          className="w-full bg-slate-900 hover:bg-slate-800 text-white font-bold py-3 px-6 rounded-xl transition-all shadow-lg flex items-center justify-center gap-2 disabled:opacity-70"
                      >
                          {isVerifying ? <Loader2 className="animate-spin" size={20}/> : <span className="flex items-center gap-2">Verify Access <ArrowRight size={18}/></span>}
                      </button>
                  </div>
              </div>
          )}

          {step === 'connect' && (
              <div className="animate-in slide-in-from-right-4 duration-300">
                {status === 'success' ? (
                    <div className="text-center space-y-4">
                    <div className="mx-auto w-12 h-12 bg-emerald-100 text-emerald-600 rounded-full flex items-center justify-center">
                        <CheckCircle size={24} />
                    </div>
                    <h3 className="text-lg font-bold text-emerald-700">All Set!</h3>
                    <p className="text-slate-600">{message}</p>
                    <p className="text-xs text-slate-400 mt-4">It is safe to close this window now.</p>
                    </div>
                ) : status === 'error' ? (
                    <div className="text-center space-y-4">
                    <div className="mx-auto w-12 h-12 bg-rose-100 text-rose-600 rounded-full flex items-center justify-center">
                        <AlertTriangle size={24} />
                    </div>
                    <h3 className="text-lg font-bold text-rose-700">Connection Failed</h3>
                    <p className="text-slate-600">{message}</p>
                    <button 
                        onClick={() => setStatus('idle')}
                        className="text-blue-600 hover:text-blue-800 font-medium text-sm hover:underline mt-2"
                    >
                        Try Again
                    </button>
                    </div>
                ) : (
                    <div className="space-y-6">
                        <div className="bg-emerald-50 border border-emerald-100 p-3 rounded-lg flex items-center gap-3 mb-6">
                            <CheckCircle className="text-emerald-600" size={20} />
                            <div>
                                <p className="text-sm font-bold text-emerald-800">Verified Account</p>
                                <p className="text-xs text-emerald-600">ID: {username}</p>
                            </div>
                        </div>

                        <div className="space-y-3">
                            <div className="flex gap-3 text-sm text-slate-600">
                                <CheckCircle size={18} className="text-blue-500 flex-shrink-0" />
                                <p>Connect your Facebook Page & Instagram</p>
                            </div>
                            <div className="flex gap-3 text-sm text-slate-600">
                                <CheckCircle size={18} className="text-blue-500 flex-shrink-0" />
                                <p>Enable automated scheduled posts</p>
                            </div>
                        </div>

                        <button 
                            onClick={handleConnect}
                            className="w-full flex items-center justify-center gap-3 bg-[#1877F2] hover:bg-[#166fe5] text-white font-bold py-3 px-6 rounded-xl transition-all shadow-lg shadow-blue-900/10 hover:shadow-blue-900/20 transform hover:-translate-y-0.5"
                        >
                            <Facebook size={24} />
                            Connect with Facebook
                        </button>
                        
                        <p className="text-center text-xs text-slate-400">
                            You will be redirected to Meta to approve permissions.
                        </p>
                    </div>
                )}
            </div>
          )}
        </div>
        
        {/* Footer */}
        <div className="bg-slate-50 p-4 border-t border-slate-100">
           <div className="flex flex-wrap justify-center gap-4 text-xs text-slate-400 mb-2">
             <a href="#privacy" className="hover:text-slate-600 hover:underline">Privacy Policy</a>
             <span>|</span>
             <a href="#terms" className="hover:text-slate-600 hover:underline">Terms of Service</a>
             <span>|</span>
             <a href="#data_deletion" className="hover:text-slate-600 hover:underline">Data Deletion</a>
           </div>
           <p className="text-center text-xs text-slate-400">Powered by SocialSync Broadcast</p>
        </div>
      </div>
    </div>
  );
};
