import { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  CircularProgress,
  Alert,
  Grid,
  Card,
  CardContent,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  Divider,
} from '@mui/material';
import { getResults } from '../services/api';

export default function Results() {
  const [results, setResults] = useState({ completed: [], in_progress: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedParticipant, setSelectedParticipant] = useState('all');
  const [participants, setParticipants] = useState([]);

  useEffect(() => {
    const fetchResults = async () => {
      try {
        setLoading(true);
        const data = await getResults(null, selectedParticipant);
        console.log('Fetched results:', data); // Debug log
        if (data && (data.completed || data.in_progress)) {
          setResults({
            completed: data.completed || [],
            in_progress: data.in_progress || []
          });
          
          // Extract unique participants
          const participantSet = new Set();
          [...(data.completed || []), ...(data.in_progress || [])].forEach(result => {
            if (result.participant_name) {
              participantSet.add(result.participant_name);
            }
          });
          setParticipants(Array.from(participantSet));
        } else {
          setError('Formato de resultados inválido recibido del servidor');
        }
      } catch (err) {
        console.error('Error fetching results:', err);
        setError(err.message || 'Error al cargar los resultados');
      } finally {
        setLoading(false);
      }
    };

    fetchResults();
  }, [selectedParticipant]);

  const getScoreColor = (score) => {
    if (score >= 80) return '#4caf50';
    if (score >= 60) return '#2196f3';
    if (score >= 40) return '#ff9800';
    return '#f44336';
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Alert severity="error">{error}</Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          Resultados de Evaluación de Asertividad
        </Typography>

        {participants.length > 0 && (
          <FormControl sx={{ minWidth: 200 }}>
            <InputLabel>Filtrar por Participante</InputLabel>
            <Select
              value={selectedParticipant}
              onChange={(e) => setSelectedParticipant(e.target.value)}
              label="Filtrar por Participante"
            >
              <MenuItem value="all">Todos los Participantes</MenuItem>
              {participants.map((participant) => (
                <MenuItem key={participant} value={participant}>
                  {participant}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        )}
      </Box>

      {results.completed.length > 0 && (
        <Box sx={{ mb: 4 }}>
          <Typography variant="h5" gutterBottom>
            Evaluaciones Completadas ({results.completed.length})
          </Typography>
          <Grid container spacing={3}>
            {results.completed.map((result) => (
              <Grid item xs={12} key={result.id}>
                <Paper elevation={3}>
                  <Box p={3}>
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={4}>
                        <Typography variant="h6" gutterBottom>
                          {result.participant_name}
                        </Typography>
                        <Typography color="textSecondary" gutterBottom>
                          Completado: {new Date(result.completed_at).toLocaleString()}
                        </Typography>
                        <Box sx={{ mt: 2 }}>
                          <Chip
                            label={`${result.score}%`}
                            sx={{
                              bgcolor: getScoreColor(result.score),
                              color: 'white',
                              fontSize: '1.1rem',
                              fontWeight: 'bold',
                              mr: 1
                            }}
                          />
                          <Chip
                            label={result.level}
                            variant="outlined"
                            sx={{ mr: 1 }}
                          />
                        </Box>
                      </Grid>
                      <Grid item xs={12} md={8}>
                        <Typography variant="h6" gutterBottom>
                          Retroalimentación
                        </Typography>
                        <Typography>
                          {result.feedback}
                        </Typography>
                        <Box sx={{ mt: 2 }}>
                          <Typography variant="subtitle2" color="textSecondary">
                            Resumen de Respuestas:
                          </Typography>
                          {Object.entries(result.responses).map(([questionId, answerIndex]) => (
                            <Typography key={questionId} variant="body2" color="textSecondary">
                              Pregunta {questionId}: Opción {parseInt(answerIndex) + 1}
                            </Typography>
                          ))}
                        </Box>
                      </Grid>
                    </Grid>
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {results.in_progress.length > 0 && (
        <Box>
          <Typography variant="h5" gutterBottom>
            En Progreso ({results.in_progress.length})
          </Typography>
          <Grid container spacing={3}>
            {results.in_progress.map((result) => (
              <Grid item xs={12} md={6} key={result.id}>
                <Card>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      {result.assessment_title}
                    </Typography>
                    <Typography color="textSecondary">
                      Participante: {result.participant_name}
                    </Typography>
                    <Typography color="textSecondary">
                      Iniciado: {new Date(result.started_at).toLocaleString()}
                    </Typography>
                    <Typography>
                      Progreso: {Math.round((Object.keys(result.responses || {}).length / 5) * 100)}%
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {(!results.completed || results.completed.length === 0) && 
       (!results.in_progress || results.in_progress.length === 0) && (
        <Alert severity="info">
          No se encontraron resultados
          {selectedParticipant !== 'all' && ` para ${selectedParticipant}`}.
        </Alert>
      )}
    </Container>
  );
}
