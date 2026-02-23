// Service client pour appels API
// À utiliser dans tous les composants React

import axios from 'axios';
import { API_URL } from '../config';

function translateBackendMessageToFrench(message) {
  if (typeof message !== 'string' || !message) return message;
  const map = {
    'Access denied': 'Accès refusé.',
    'File not found': 'Fichier introuvable.',
    'Folder not found': 'Dossier introuvable.',
    'Parent folder not found': 'Dossier parent introuvable.',
    'Invalid credentials': 'Identifiants incorrects.',
    'Invalid password': 'Mot de passe invalide.',
    'Password required': 'Mot de passe requis.',
    'Share expired': 'Partage expiré.',
    'Share deactivated': 'Partage désactivé.',
    'Share created': 'Partage créé.',
    'Internal Server Error': 'Erreur interne du serveur',
  };

  return map[message] || message;
}

function localizeAxiosErrorInPlace(error) {
  const apiMessage = error?.response?.data?.error?.message;
  if (typeof apiMessage === 'string') {
    error.response.data.error.message = translateBackendMessageToFrench(apiMessage);
  }
  return error;
}

function readPersistedAuthState() {
  try {
    const raw = localStorage.getItem('auth-storage');
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed?.state && typeof parsed.state === 'object' ? parsed.state : null;
  } catch {
    return null;
  }
}

function getAuthTokens() {
  let accessToken = localStorage.getItem('access_token');
  let refreshToken = localStorage.getItem('refresh_token');

  // Fallback: Zustand persist peut contenir des tokens même si localStorage access_token a été effacé.
  if (!accessToken || !refreshToken) {
    const state = readPersistedAuthState();
    accessToken = accessToken || state?.accessToken || null;
    refreshToken = refreshToken || state?.refreshToken || null;

    // Réécrire localStorage pour que les intercepteurs et fetch() restent cohérents.
    if (accessToken) localStorage.setItem('access_token', accessToken);
    if (refreshToken) localStorage.setItem('refresh_token', refreshToken);
  }

  return { accessToken, refreshToken };
}

// API_URL est maintenant importé depuis config.js avec la valeur par défaut pour la production

// Créer une instance axios avec configuration par défaut
const apiClient = axios.create({
  baseURL: `${API_URL}`,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 20000, // 20 s : éviter chargement infini si le backend ne répond pas (CORS, crash, etc.)
});

// Instance dédiée aux endpoints d'auth (évite d'envoyer un Bearer potentiellement expiré sur /auth/refresh)
const authClient = axios.create({
  baseURL: `${API_URL}`,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 20000,
});

// Instance séparée pour les uploads (sans Content-Type par défaut)
const uploadClient = axios.create({
  baseURL: `${API_URL}`,
});

// Intercepteur pour ajouter le JWT à chaque requête
apiClient.interceptors.request.use((config) => {
  const { accessToken } = getAuthTokens();
  if (!config.headers) config.headers = {};
  if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`;
  // Ne pas logger l'URL ni l'absence de token en production (éviter fuite d'infos)
  return config;
}, (error) => {
  return Promise.reject(error);
});

// Intercepteur pour les uploads - ajouter le token mais laisser Content-Type géré par le navigateur
uploadClient.interceptors.request.use((config) => {
  const { accessToken } = getAuthTokens();
  if (!config.headers) config.headers = {};
  if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`;
  // Ne pas définir Content-Type - laisser le navigateur le faire pour FormData
  return config;
}, (error) => {
  return Promise.reject(error);
});

// Intercepteur pour gérer les erreurs (notamment 401) et mode hors ligne - pour apiClient
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    localizeAxiosErrorInPlace(error);
    // Détection mode hors ligne : message explicite pour l'utilisateur
    if (typeof navigator !== 'undefined' && !navigator.onLine) {
      const offlineError = new Error('Vous êtes hors ligne. Les données ne sont pas disponibles sans connexion Internet.');
      offlineError.isOffline = true;
      return Promise.reject(offlineError);
    }
    if (error.code === 'ERR_NETWORK' || error.message === 'Network Error') {
      const networkError = new Error('Connexion impossible. Vérifiez votre connexion Internet.');
      networkError.isOffline = true;
      return Promise.reject(networkError);
    }
    if (error.response?.status === 401) {
      // Prevent infinite refresh loops (e.g. if /auth/refresh itself returns 401)
      const requestUrl = (error.config?.url || '').toString();
      const isAuthRefreshRequest = requestUrl.includes('/auth/refresh');
      const alreadyRetried = !!error.config?._retry;

      const code = error.response?.data?.error?.code;
      const msg = error.response?.data?.error?.message;
      const setDeletedMsgAndRedirect = (message) => {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        // Purger aussi le store persisté sinon ProtectedRoute peut croire qu'on est encore connecté.
        localStorage.removeItem('auth-storage');
        sessionStorage.setItem('deleted_account_message', message || 'Veuillez vous inscrire et vous connecter pour accéder à Supfile, votre espace de stockage.');
        window.location.href = '/login';
      };

      // If refresh endpoint is unauthorized or we already retried once, force logout.
      if (isAuthRefreshRequest || alreadyRetried) {
        setDeletedMsgAndRedirect(null);
        return Promise.reject(error);
      }

      // Compte supprimé : ne pas tenter refresh, déconnecter et afficher le message approprié
      if (code === 'USER_DELETED') {
        setDeletedMsgAndRedirect(msg || 'Votre compte a été supprimé.');
        return Promise.reject(error);
      }
      // Token expiré - essayer de rafraîchir
      const { refreshToken } = getAuthTokens();
      if (refreshToken) {
        try {
          const response = await authService.refresh(refreshToken);
          const { access_token, refresh_token } = response.data.data;
          localStorage.setItem('access_token', access_token);
          localStorage.setItem('refresh_token', refresh_token);
          
          error.config._retry = true;
          if (!error.config.headers) error.config.headers = {};
          error.config.headers.Authorization = `Bearer ${access_token}`;
          return apiClient.request(error.config);
        } catch (refreshError) {
          const refreshCode = refreshError.response?.data?.error?.code;
          const refreshMsg = refreshError.response?.data?.error?.message;
          if (refreshCode === 'USER_DELETED') {
            setDeletedMsgAndRedirect(refreshMsg);
          } else {
            setDeletedMsgAndRedirect(null);
          }
          return Promise.reject(refreshError);
        }
      } else {
        setDeletedMsgAndRedirect(null);
        return Promise.reject(error);
      }
    }
    return Promise.reject(error);
  },
);

// Intercepteur équivalent pour les endpoints d'auth (traduction + offline/network)
authClient.interceptors.response.use(
  (response) => response,
  (error) => {
    localizeAxiosErrorInPlace(error);

    if (typeof navigator !== 'undefined' && !navigator.onLine) {
      const offlineError = new Error('Vous êtes hors ligne. Les données ne sont pas disponibles sans connexion Internet.');
      offlineError.isOffline = true;
      return Promise.reject(offlineError);
    }
    if (error.code === 'ERR_NETWORK' || error.message === 'Network Error') {
      const networkError = new Error('Connexion impossible. Vérifiez votre connexion Internet.');
      networkError.isOffline = true;
      return Promise.reject(networkError);
    }

    return Promise.reject(error);
  },
);

// Services d'authentification
export const authService = {
  signup: (email, password, first_name, last_name, country) =>
    authClient.post('/auth/signup', { email, password, first_name, last_name, country }),
  login: (email, password) =>
    authClient.post('/auth/login', { email, password }),
  refresh: (refreshToken) =>
    authClient.post('/auth/refresh', { refresh_token: refreshToken }),
  logout: (refreshToken) => authClient.post('/auth/logout', { refresh_token: refreshToken }),
  verifyEmail: (token) =>
    authClient.get('/auth/verify-email', { params: { token } }),
  resendVerification: (email) =>
    authClient.post('/auth/resend-verification', { email }),
};

// Services fichiers
export const fileService = {
  list: (folderId = null) =>
    apiClient.get('/files', { params: { folder_id: folderId } }),
  get: (fileId) => apiClient.get(`/files/${fileId}`),
  upload: (file, folderId = null, onProgress = null) => {
    const formData = new FormData();
    formData.append('file', file);
    if (folderId) formData.append('folder_id', folderId);
    
    const config = {};
    
    if (onProgress) {
      config.onUploadProgress = (progressEvent) => {
        const percentCompleted = Math.round(
          (progressEvent.loaded * 100) / progressEvent.total,
        );
        onProgress(percentCompleted);
      };
    }
    
    // Utiliser uploadClient qui n'a pas de Content-Type par défaut
    return uploadClient.post('/files/upload', formData, config);
  },
  initChunkedUpload: ({ name, size, mimeType, folderId }) => {
    // L'initialisation peut être lente selon le backend/stockage.
    // On augmente le timeout par requête pour éviter un blocage à 99% côté UI.
    return apiClient.post(
      '/files/upload/init',
      {
        name,
        size,
        mime_type: mimeType,
        folder_id: folderId,
      },
      { timeout: 120000 },
    );
  },
  uploadChunk: ({ uploadId, chunkIndex, totalChunks, chunk, signal }, onProgress = null) => {
    const formData = new FormData();
    formData.append('upload_id', uploadId);
    formData.append('chunk_index', String(chunkIndex));
    formData.append('total_chunks', String(totalChunks));
    formData.append('chunk', chunk);

    const config = {};
    if (onProgress) {
      config.onUploadProgress = (progressEvent) => {
        const percentCompleted = Math.round(
          (progressEvent.loaded * 100) / progressEvent.total,
        );
        onProgress(percentCompleted);
      };
    }
    if (signal) {
      config.signal = signal;
    }

    return uploadClient.post('/files/upload/chunk', formData, config);
  },
  completeChunkedUpload: ({ uploadId, totalChunks }) => {
    // L'assemblage serveur peut durer (gros fichiers). Timeout long.
    return apiClient.post(
      '/files/upload/complete',
      {
        upload_id: uploadId,
        total_chunks: totalChunks,
      },
      { timeout: 10 * 60 * 1000 },
    );
  },
  getChunkedUploadStatus: (uploadId) =>
    apiClient.get('/files/upload/status', { params: { upload_id: uploadId }, timeout: 120000 }),
  download: (fileId) => apiClient.get(`/files/${fileId}/download`),
  downloadBlob: (fileId) => apiClient.get(`/files/${fileId}/download`, { responseType: 'blob' }),
  delete: (fileId) => apiClient.delete(`/files/${fileId}`),
  restore: (fileId) => apiClient.post(`/files/${fileId}/restore`),
  listTrash: () => apiClient.get('/files/trash'),
  rename: (fileId, newName) =>
    apiClient.patch(`/files/${fileId}`, { name: newName }),
  move: (fileId, newFolderId) =>
    apiClient.patch(`/files/${fileId}`, { folder_id: newFolderId }),
  preview: (fileId) => apiClient.get(`/files/${fileId}/preview`),
  stream: (fileId) => apiClient.get(`/files/${fileId}/stream`),
};

// Services dossiers
export const folderService = {
  create: (name, parentId = null) =>
    apiClient.post('/folders', { name, parent_id: parentId }),
  get: (folderId) => apiClient.get(`/folders/${folderId}`),
  rename: (folderId, newName) =>
    apiClient.patch(`/folders/${folderId}`, { name: newName }),
  move: (folderId, newParentId) =>
    apiClient.patch(`/folders/${folderId}`, { parent_id: newParentId }),
  delete: (folderId) => apiClient.delete(`/folders/${folderId}`),
  restore: (folderId) => apiClient.post(`/folders/${folderId}/restore`),
  listTrash: () => apiClient.get('/folders/trash'),
  list: (parentId = null) =>
    apiClient.get('/folders', { params: { parent_id: parentId || null } }),
  listAll: () => apiClient.get('/folders/all'),
};

// Services partage
export const shareService = {
  generatePublicLink: (fileId, options = {}) =>
    apiClient.post('/share/public', {
      file_id: fileId,
      password: options.password,
      expires_at: options.expiresAt,
    }),
  generateFolderLink: (folderId, options = {}) =>
    apiClient.post('/share/public', {
      folder_id: folderId,
      password: options.password,
      expires_at: options.expiresAt,
    }),
  shareWithUser: (fileId, folderId, userId) =>
    apiClient.post('/share/internal', { 
      file_id: fileId || null, 
      folder_id: folderId || null,
      shared_with_user_id: userId 
    }),
  getPublicShare: (token, password = null) => {
    const params = password ? { password } : {};
    return apiClient.get(`/share/${token}`, {
      params,
      validateStatus: () => true, // Autoriser 404, etc.
    });
  },
};

// Services utilisateur
export const userService = {
  getMe: () => apiClient.get('/users/me'),
  listUsers: (search = '') =>
    apiClient.get('/users', { params: { search } }),
  updateProfile: (data) =>
    apiClient.patch('/users/me', data),
  changePassword: (currentPassword, newPassword) =>
    apiClient.patch('/users/me/password', {
      current_password: currentPassword,
      new_password: newPassword,
    }),
  // Le backend attend un objet { preferences: {...} }
  updatePreferences: (preferences) =>
    apiClient.patch('/users/me/preferences', { preferences }),
};

// Services dashboard
export const dashboardService = {
  getStats: () => apiClient.get('/dashboard'),
  search: (query, filters = {}) =>
    apiClient.get('/search', {
      params: { q: query, ...filters },
    }),
};

export default apiClient;
