// Frontend API Utilities with Authentication Support

interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
}

declare global {
  interface ImportMeta {
    readonly env: ImportMetaEnv;
  }
}

const getApiUrl = (): string => {
  const apiUrl = import.meta.env.VITE_API_URL;
  if (apiUrl) {
    return apiUrl;
  }
  return '/api';
};

export const API_URL = getApiUrl();

// --- Auth Utils ---

export const getAuthToken = (): string | null => {
  return localStorage.getItem('authToken');
};

export const setAuthToken = (token: string) => {
  localStorage.setItem('authToken', token);
};

export const removeAuthToken = () => {
  localStorage.removeItem('authToken');
};

// --- Fetch Wrapper ---

export interface ApiRequestOptions extends RequestInit {
  headers?: Record<string, string>;
}

export const apiFetch = async (endpoint: string, options: ApiRequestOptions = {}): Promise<Response> => {
  const token = getAuthToken();
  const headers = { ...options.headers };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Ensure Content-Type is set for JSON bodies unless explicitly handled (like FormData)
  if (!headers['Content-Type'] && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  // Remove Content-Type for FormData so browser sets boundary
  if (options.body instanceof FormData && headers['Content-Type']) {
     delete headers['Content-Type'];
  }

  const url = endpoint.startsWith('http') ? endpoint : `${API_URL}${endpoint}`;

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    // Handle token expiry or unauthorized access
    console.warn('Unauthorized access. Redirecting to login.');
    removeAuthToken();
    localStorage.removeItem('isAuthenticated');
    localStorage.removeItem('currentUsername');
    window.location.hash = ''; // Reloads app to login state usually
    window.location.reload();
  }

  return response;
};