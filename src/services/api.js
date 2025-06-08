import axios from 'axios';

// Backend desplegado en Render
const API_URL = import.meta.env.VITE_API_URL || "https://assessment-platform-1nuo.onrender.com";

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Para mantener las cookies de sesión
});

export const login = async (username, password) => {
  try {
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    
    const response = await api.post('/login', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      maxRedirects: 0, // No seguir redirects automáticamente
      validateStatus: function (status) {
        return status >= 200 && status < 400; // Aceptar redirects como éxito
      }
    });
    
    // Si obtenemos un 302 redirect al dashboard, el login fue exitoso
    if (response.status === 302 || response.status === 200) {
      return { success: true, user: { username } };
    }
    
    return { success: true, user: { username } };
  } catch (error) {
    // Si es un error 401 o 400, las credenciales son incorrectas
    if (error.response?.status === 401 || error.response?.status === 400) {
      throw new Error('Usuario o contraseña incorrectos');
    }
    throw error.response?.data || error.message;
  }
};

export const logout = async () => {
  try {
    const response = await api.get('/logout');
    return { success: true };
  } catch (error) {
    throw error.response?.data || error.message;
  }
};

export const getAssessments = async () => {
  try {
    const response = await api.get('/api/assessments');
    return response.data.assessments || [];
  } catch (error) {
    throw error.response?.data || error.message;
  }
};

export const getDashboard = async () => {
  try {
    const response = await api.get('/dashboard');
    return { success: true, data: response.data };
  } catch (error) {
    throw error.response?.data || error.message;
  }
};

export const saveProgress = async (assessmentId, userId, data) => {
  try {
    const response = await api.post(`/api/assessment/${assessmentId}/save`, data);
    return response.data;
  } catch (error) {
    throw error.response?.data || error.message;
  }
};

export const getResults = async (userId, participant = 'all') => {
  try {
    const response = await api.get('/api/results', {
      params: { participant }
    });
    return response.data;
  } catch (error) {
    throw error.response?.data || error.message;
  }
};
