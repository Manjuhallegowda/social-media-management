
import React, { useState } from 'react';
import { 
  LayoutDashboard, 
  Users, 
  PenSquare, 
  History, 
  Settings,
  ChevronDown,
  ChevronRight,
  Shield,
  FileText,
  Trash2,
  Menu,
  X
} from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
  currentView: string;
  onViewChange: (view: any) => void;
}

export const Layout: React.FC<LayoutProps> = ({ children, currentView, onViewChange }) => {
  const [expandedMenus, setExpandedMenus] = useState<Record<string, boolean>>({
    'accounts-group': true // Default open
  });
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const toggleMenu = (id: string) => {
    setExpandedMenus(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleNavClick = (viewId: string) => {
      onViewChange(viewId);
      setIsMobileMenuOpen(false); // Close mobile menu on navigation
  };

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { 
      id: 'accounts-group', 
      label: 'Accounts', 
      icon: Users,
      children: [
        { id: 'accounts', label: 'Connected Accounts' },
        { id: 'access_control', label: 'Access Control' }
      ]
    },
    { id: 'create_post', label: 'Create Post', icon: PenSquare },
    { id: 'post_history', label: 'History', icon: History },
  ];

  return (
    <div className="flex h-screen bg-slate-50 overflow-hidden">
      
      {/* Mobile Menu Overlay */}
      {isMobileMenuOpen && (
        <div 
            className="fixed inset-0 bg-slate-900/50 z-20 md:hidden backdrop-blur-sm"
            onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`
        fixed inset-y-0 left-0 z-30 w-64 bg-slate-900 text-slate-50 flex flex-col transition-transform duration-300 ease-in-out
        md:translate-x-0 md:static md:inset-auto
        ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        <div className="p-6 flex justify-between items-center">
          <div>
            <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400">
                SocialSync
            </h1>
            <p className="text-xs text-slate-400 mt-1">Multi-Tenant Broadcaster</p>
          </div>
          <button 
            onClick={() => setIsMobileMenuOpen(false)} 
            className="md:hidden text-slate-400 hover:text-white"
          >
            <X size={24} />
          </button>
        </div>

        <nav className="flex-1 px-4 space-y-2 overflow-y-auto custom-scrollbar">
          {navItems.map((item) => {
            const Icon = item.icon;
            
            // Check if item has children (Submenu)
            if (item.children) {
              const isExpanded = expandedMenus[item.id];
              const isActiveParent = item.children.some(child => child.id === currentView);
              
              return (
                <div key={item.id} className="space-y-1">
                  <button
                    onClick={() => toggleMenu(item.id)}
                    className={`w-full flex items-center justify-between px-4 py-3 rounded-lg transition-colors ${
                      isActiveParent 
                        ? 'text-white' 
                        : 'text-slate-400 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      <Icon size={20} />
                      <span className="font-medium">{item.label}</span>
                    </div>
                    {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                  </button>
                  
                  {isExpanded && (
                    <div className="pl-11 space-y-1">
                      {item.children.map(child => (
                         <button
                           key={child.id}
                           onClick={() => handleNavClick(child.id)}
                           className={`w-full text-left block px-3 py-2 rounded-lg text-sm transition-colors ${
                             currentView === child.id 
                               ? 'bg-blue-600 text-white shadow-sm' 
                               : 'text-slate-500 hover:text-white hover:bg-slate-800'
                           }`}
                         >
                           {child.label}
                         </button>
                      ))}
                    </div>
                  )}
                </div>
              );
            }

            // Standard Item
            const isActive = currentView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.id)}
                className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${
                  isActive 
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/50' 
                    : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                }`}
              >
                <Icon size={20} />
                <span className="font-medium">{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800">
          <button 
            onClick={() => handleNavClick('settings')}
            className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${
              currentView === 'settings' 
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/50' 
                : 'text-slate-400 hover:bg-slate-800 hover:text-white'
            }`}
          >
            <Settings size={20} />
            <span className="font-medium">Settings</span>
          </button>
          
          {/* Legal Pages Links */}
          <div className="mt-4 pt-4 border-t border-slate-800 space-y-1">
             <button onClick={() => handleNavClick('privacy')} className="w-full flex items-center gap-3 px-4 py-2 text-xs text-slate-500 hover:text-white transition-colors rounded-lg hover:bg-slate-800">
                 <Shield size={14} /> Privacy Policy
             </button>
             <button onClick={() => handleNavClick('terms')} className="w-full flex items-center gap-3 px-4 py-2 text-xs text-slate-500 hover:text-white transition-colors rounded-lg hover:bg-slate-800">
                 <FileText size={14} /> Terms of Service
             </button>
             <button onClick={() => handleNavClick('data_deletion')} className="w-full flex items-center gap-3 px-4 py-2 text-xs text-slate-500 hover:text-white transition-colors rounded-lg hover:bg-slate-800">
                 <Trash2 size={14} /> Data Deletion
             </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Mobile Header */}
        <header className="bg-white border-b border-slate-200 p-4 flex items-center justify-between md:hidden shrink-0 shadow-sm z-10">
             <div className="flex items-center gap-2">
                <span className="font-bold text-lg text-slate-800">SocialSync</span>
             </div>
             <button onClick={() => setIsMobileMenuOpen(true)} className="text-slate-600 hover:text-slate-900 p-1">
                <Menu size={24}/>
             </button>
        </header>

        <main className="flex-1 overflow-y-auto bg-slate-50 p-4 md:p-8">
            <div className="max-w-7xl mx-auto">
                {children}
            </div>
        </main>
      </div>
    </div>
  );
};
