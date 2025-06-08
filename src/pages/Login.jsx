import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  TextField,
  Button,
  Typography,
  Box,
  Alert,
} from '@mui/material';
import { login } from '../services/api';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      const response = await login(username, password);
      if (response.success) {
        onLogin(response.user);
        navigate('/dashboard');
      }
    } catch (err) {
      setError('Usuario o contraseña incorrectos');
      console.error('Login error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="sm">
      <Box sx={{ mt: 8 }}>
        <Paper elevation={3} sx={{ p: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom align="center">
            Iniciar Sesión
          </Typography>
          <Typography variant="body2" align="center" sx={{ mb: 3, color: 'text.secondary' }}>
            Plataforma de Evaluación de Asertividad
          </Typography>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          <form onSubmit={handleSubmit}>
            <TextField
              fullWidth
              label="Usuario"
              margin="normal"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              disabled={loading}
            />
            <TextField
              fullWidth
              label="Contraseña"
              type="password"
              margin="normal"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={loading}
            />
            <Button
              type="submit"
              fullWidth
              variant="contained"
              color="primary"
              sx={{ mt: 3 }}
              disabled={loading}
            >
              {loading ? 'Iniciando sesión...' : 'Iniciar Sesión'}
            </Button>
          </form>
          <Box sx={{ mt: 3, p: 2, backgroundColor: '#f5f5f5', borderRadius: 1 }}>
            <Typography variant="body2" align="center" sx={{ fontWeight: 'bold' }}>
              Credenciales de prueba:
            </Typography>
            <Typography variant="body2" align="center">
              Usuario: admin | Contraseña: admin123
            </Typography>
          </Box>
        </Paper>
      </Box>
    </Container>
  );
}
