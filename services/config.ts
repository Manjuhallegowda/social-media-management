const getApiUrl = (): string => {
  const apiUrl = import.meta.env.VITE_API_URL;
  if (apiUrl) {
    return apiUrl;
  }
  // For production, you might want to throw an error if the API URL is not set.
  // For development, we can fall back to a proxy.
  return '/api';
};

export const API_URL = getApiUrl();
