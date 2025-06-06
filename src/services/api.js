import axios from 'axios';

// Cambia este valor por la URL de tu backend en Render, por ejemplo:
// const API_URL = "https://tu-backend.onrender.com";
// O usa la variable de entorno VITE_API_URL para mayor flexibilidad:
const API_URL = import.meta.env.VITE_API_URL || "https://TU_BACKEND_RENDER_URL";

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const login = async (username, password) => {
  try {
    const response = await api.post('/api/login', { username, password });
    return response.data;
  } catch (error) {
    throw error.response?.data || error.message;
  }
};

export const getAssessments = async () => {
  try {
    const response = await api.get('/api/assessments');
    return response.data.assessments;
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
