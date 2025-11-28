import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { PrivacyPolicy } from './components/LegalPages';
import { AccountsPage } from './components/AccountsPage';
import { OnboardingPage } from './components/OnboardingPage';

// Fix TS errors for Jest globals
declare const jest: any;
declare const describe: any;
declare const test: any;
declare const expect: any;
declare const beforeEach: any;
declare const global: any;

// Mock window.open to verify it's called instead of location.href
const mockOpen = jest.fn();
window.open = mockOpen;

// Mock Clipboard API
const mockWriteText = jest.fn();
Object.assign(navigator, {
  clipboard: {
    writeText: mockWriteText,
  },
});

// Mock fetch for API calls
global.fetch = jest.fn() as any;

beforeEach(() => {
  jest.clearAllMocks();
  // Reset hash
  window.location.hash = '';
});

describe('Legal Pages Navigation', () => {
  test('Privacy Policy "Back to App" button navigates to dashboard via hash', () => {
    render(<PrivacyPolicy />);
    
    const backButton = screen.getByText(/Back to App/i);
    fireEvent.click(backButton);
    
    // Verify it updates the hash instead of trying to navigate away (which caused the error)
    expect(window.location.hash).toBe('#dashboard');
  });
});

describe('Accounts Page Interactions', () => {
  test('Connect Manually button opens new tab (prevents X-Frame-Options error)', () => {
    render(<AccountsPage />);
    
    const connectBtn = screen.getByText(/Connect Manually/i);
    fireEvent.click(connectBtn);
    
    expect(mockOpen).toHaveBeenCalledTimes(1);
    // Ensure it opens in a new window/tab ('SocialSyncLogin' is the window name)
    expect(mockOpen).toHaveBeenCalledWith(
      expect.stringContaining('/api/auth/login?source=admin'),
      'SocialSyncLogin',
      expect.stringContaining('width=600')
    );
  });

  test('Copy Invite Link writes to clipboard', () => {
    render(<AccountsPage />);
    
    const copyBtn = screen.getByText(/Copy Invite Link/i);
    fireEvent.click(copyBtn);
    
    expect(mockWriteText).toHaveBeenCalledWith(expect.stringContaining('#onboarding'));
    
    // Check for success notification
    expect(screen.getByText(/Invite link copied/i)).toBeInTheDocument();
  });
});

describe('Onboarding Page Interactions', () => {
  test('Verification flow leads to Connect button which opens new tab', async () => {
    // Mock successful verification response
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ verified: true }),
    });

    render(<OnboardingPage />);
    
    // 1. Enter Username
    const input = screen.getByPlaceholderText(/e.g. business_page_name/i);
    fireEvent.change(input, { target: { value: 'test-page' } });
    
    // 2. Click Verify
    const verifyBtn = screen.getByText(/Verify Access/i);
    fireEvent.click(verifyBtn);
    
    // 3. Wait for Connect Button (Step change)
    await waitFor(() => {
      expect(screen.getByText(/Connect with Facebook/i)).toBeInTheDocument();
    });
    
    // 4. Click Connect
    const connectBtn = screen.getByText(/Connect with Facebook/i);
    fireEvent.click(connectBtn);
    
    // Verify window.open is used with correct source
    expect(mockOpen).toHaveBeenCalled();
    expect(mockOpen).toHaveBeenCalledWith(
      expect.stringContaining('source=onboarding'),
      'SocialSyncConnect',
      expect.stringContaining('width=600')
    );
  });
});