
import React, { useState, useEffect } from 'react';
import { Layout } from './components/Layout';
import { Dashboard } from './components/Dashboard';
import { AccountsPage } from './components/AccountsPage';
import { AccessControlPage } from './components/AccessControlPage';
import { CreatePostPage } from './components/CreatePostPage';
import { PostHistoryPage } from './components/PostHistoryPage';
import { SettingsPage } from './components/SettingsPage';
import { OnboardingPage } from './components/OnboardingPage';
import { PrivacyPolicy, TermsOfService, DataDeletion } from './components/LegalPages';

// Simple Hash-based routing for SPA without server config
enum View {
  DASHBOARD = 'dashboard',
  ACCOUNTS = 'accounts',
  ACCESS_CONTROL = 'access_control',
  CREATE_POST = 'create_post',
  POST_HISTORY = 'post_history',
  SETTINGS = 'settings',
  ONBOARDING = 'onboarding',
  PRIVACY = 'privacy',
  TERMS = 'terms',
  DATA_DELETION = 'data_deletion'
}

const App: React.FC = () => {
  // Initialize view from URL hash if present
  const [currentView, setCurrentView] = useState<View>(() => {
    const hash = window.location.hash.replace('#', '').split('?')[0]; // Split query params
    return Object.values(View).includes(hash as View) ? (hash as View) : View.DASHBOARD;
  });

  useEffect(() => {
    const handleHashChange = () => {
       const hash = window.location.hash.replace('#', '').split('?')[0];
       if (Object.values(View).includes(hash as View)) {
         setCurrentView(hash as View);
       }
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const handleViewChange = (view: View) => {
    window.location.hash = view;
    setCurrentView(view);
  };

  // Standalone Views (No Admin Sidebar)
  if (currentView === View.ONBOARDING) return <OnboardingPage />;
  if (currentView === View.PRIVACY) return <PrivacyPolicy />;
  if (currentView === View.TERMS) return <TermsOfService />;
  if (currentView === View.DATA_DELETION) return <DataDeletion />;

  const renderView = () => {
    switch (currentView) {
      case View.DASHBOARD:
        return <Dashboard onViewChange={handleViewChange} />;
      case View.ACCOUNTS:
        return <AccountsPage />;
      case View.ACCESS_CONTROL:
        return <AccessControlPage />;
      case View.CREATE_POST:
        return <CreatePostPage />;
      case View.POST_HISTORY:
        return <PostHistoryPage />;
      case View.SETTINGS:
        return <SettingsPage />;
      default:
        return <Dashboard onViewChange={handleViewChange} />;
    }
  };

  return (
    <Layout currentView={currentView} onViewChange={handleViewChange}>
      {renderView()}
    </Layout>
  );
};

export default App;
