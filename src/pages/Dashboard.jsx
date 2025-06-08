import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Container,
  Grid,
  Card,
  CardContent,
  CardActions,
  Typography,
  Button,
  Box,
  CircularProgress,
  Alert,
} from '@mui/material';
import { getAssessments } from '../services/api';

export default function Dashboard() {
  const [assessments, setAssessments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchAssessments = async () => {
      try {
        const data = await getAssessments();
        setAssessments(data);
      } catch (err) {
        setError(err.message || 'Failed to load assessments');
      } finally {
        setLoading(false);
      }
    };

    fetchAssessments();
  }, []);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Evaluaciones Disponibles
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Grid container spacing={3}>
        {assessments.map((assessment) => (
          <Grid item xs={12} sm={6} md={4} key={assessment.id}>
            <Card>
              <CardContent>
                <Typography variant="h5" component="h2" gutterBottom>
                  {assessment.title}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {assessment.description}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Preguntas: {assessment.questions.length}
                </Typography>
              </CardContent>
              <CardActions>
                <Button
                  component={Link}
                  to={`/assessment/${assessment.id}`}
                  variant="contained"
                  color="primary"
                  fullWidth
                >
                  Realizar Evaluación
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>

      {assessments.length === 0 && !error && (
        <Alert severity="info">No hay evaluaciones disponibles en este momento.</Alert>
      )}
    </Container>
  );
}
