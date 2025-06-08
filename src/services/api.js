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
  console.log('🔐 API login called with:', { username, password: '***' });
  
  try {
    console.log('📡 Sending POST request to:', `${API_URL}/api/login`);
    
    const response = await api.post('/api/login', {
      username,
      password
    });
    
    console.log('📨 Response received:', {
      status: response.status,
      data: response.data
    });
    
    if (response.data.success) {
      console.log('✅ Login successful!');
      return {
        success: true,
        user: response.data.user
      };
    } else {
      console.log('❌ Login failed:', response.data.error);
      throw new Error(response.data.error || 'Error de login');
    }
    
  } catch (error) {
    console.error('❌ Login API error:', error);
    
    if (error.response?.data?.error) {
      throw new Error(error.response.data.error);
    } else if (error.response?.status === 401) {
      throw new Error('Usuario o contraseña incorrectos');
    }
    
    throw new Error(error.message || 'Error de conexión');
  }
};

export const logout = async () => {
  try {
    const response = await api.post('/api/logout');
    return { success: true };
  } catch (error) {
    // Even if logout fails, we still want to clear local state
    return { success: true };
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
