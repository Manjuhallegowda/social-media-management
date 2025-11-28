import React from 'react';
import { Shield, FileText, Trash2, ArrowLeft } from 'lucide-react';

const LegalLayout: React.FC<{ title: string; icon: any; children: React.ReactNode }> = ({ title, icon: Icon, children }) => {
  return (
    <div className="min-h-screen bg-slate-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-3xl mx-auto">
        <div className="mb-6">
            <button 
                onClick={() => window.location.hash = 'dashboard'}
                className="flex items-center text-slate-500 hover:text-blue-600 transition-colors text-sm font-medium focus:outline-none"
            >
                <ArrowLeft size={16} className="mr-1" /> Back to App
            </button>
        </div>
        <div className="bg-white shadow-sm border border-slate-200 rounded-2xl overflow-hidden">
          <div className="bg-slate-900 px-8 py-6 flex items-center gap-4">
            <div className="p-2 bg-white/10 rounded-lg">
                <Icon className="text-white" size={24} />
            </div>
            <h1 className="text-2xl font-bold text-white">{title}</h1>
          </div>
          <div className="p-8 prose prose-slate max-w-none">
            {children}
          </div>
        </div>
        <div className="mt-8 text-center text-xs text-slate-400">
            &copy; {new Date().getFullYear()} SocialSync Broadcast. All rights reserved.
        </div>
      </div>
    </div>
  );
};

export const PrivacyPolicy: React.FC = () => (
  <LegalLayout title="Privacy Policy" icon={Shield}>
    <p><strong>Last Updated:</strong> {new Date().toLocaleDateString()}</p>

    <h3>1. Introduction</h3>
    <p>SocialSync Broadcast ("we", "our", or "us") is committed to protecting your privacy. This Privacy Policy explains how we collect, use, and share information about you when you use our application to manage your social media accounts.</p>

    <h3>2. Information We Collect</h3>
    <ul>
        <li><strong>Account Information:</strong> When you connect your Facebook or Instagram accounts, we collect your Page names, IDs, and Access Tokens provided by Meta.</li>
        <li><strong>Usage Data:</strong> We collect logs of the actions you take within the app (e.g., creating posts, broadcasting campaigns) to ensure system stability.</li>
        <li><strong>Content:</strong> We temporarily process the images and captions you upload to broadcast them to your connected platforms.</li>
    </ul>

    <h3>3. How We Use Your Information</h3>
    <p>We use your information solely to:</p>
    <ul>
        <li>Authenticate your identity with Meta platforms.</li>
        <li>Execute the broadcasting commands you initiate (posting to Facebook and Instagram).</li>
        <li>Monitor the success or failure of broadcast jobs.</li>
    </ul>

    <h3>4. Data Sharing</h3>
    <p>We do not sell your personal data. We only transfer data to:</p>
    <ul>
        <li><strong>Meta (Facebook/Instagram):</strong> To publish your posts via the Graph API.</li>
        <li><strong>Cloud Infrastructure:</strong> Our database and servers (Cloudflare) securely store encrypted tokens to facilitate the service.</li>
    </ul>

    <h3>5. Contact Us</h3>
    <p>If you have questions about this policy, please contact us at: <strong>privacy@example.com</strong></p>
  </LegalLayout>
);

export const TermsOfService: React.FC = () => (
  <LegalLayout title="Terms of Service" icon={FileText}>
    <p><strong>Last Updated:</strong> {new Date().toLocaleDateString()}</p>

    <h3>1. Acceptance of Terms</h3>
    <p>By accessing or using SocialSync Broadcast, you agree to be bound by these Terms of Service. If you do not agree, you may not use the service.</p>

    <h3>2. Use of Service</h3>
    <p>You are responsible for all content you post using our tool. You agree not to use the service to post illegal, abusive, or spam content.</p>

    <h3>3. Platform Availability</h3>
    <p>We rely on Meta's Graph API. We are not responsible for downtime, rate limits, or changes to Meta's API that may affect service availability.</p>

    <h3>4. Termination</h3>
    <p>We reserve the right to suspend your access to the application at any time if you violate these terms or abuse the system resources.</p>

    <h3>5. Disclaimer of Warranties</h3>
    <p>THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED.</p>
  </LegalLayout>
);

export const DataDeletion: React.FC = () => (
  <LegalLayout title="Data Deletion Instructions" icon={Trash2}>
    <p>According to the Facebook Platform rules, we provide a way for you to request that your data be deleted.</p>

    <h3>How to Remove Your Data</h3>
    <p>If you wish to remove SocialSync Broadcast's access to your data and delete our stored records of your account, please follow these steps:</p>

    <ol>
        <li>Go to your Facebook Account "Settings & Privacy".</li>
        <li>Click "Settings".</li>
        <li>Scroll down to "Permissions" and look for "Apps and Websites".</li>
        <li>Find "SocialSync Broadcast" in the list of active apps.</li>
        <li>Click the "Remove" button.</li>
        <li>Check the box that says "Delete posts, videos or events SocialSync Broadcast posted on your timeline" if you desire.</li>
        <li>Click "Remove".</li>
    </ol>

    <p>Once removed, our system will automatically fail to access your account and your tokens will become invalid. We periodically purge inactive account data from our databases.</p>

    <h3>Manual Deletion Request</h3>
    <p>If you wish for us to manually wipe all logs and database records associated with your User ID immediately, please send an email to <strong>support@example.com</strong> with the subject line "Data Deletion Request" and include your Page Name/ID.</p>
  </LegalLayout>
);