import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  Typography,
  Button,
  Box,
  TextField,
  RadioGroup,
  Radio,
  FormControlLabel,
  CircularProgress,
  Alert,
  Stepper,
  Step,
  StepLabel,
} from '@mui/material';
import { getAssessments, saveProgress } from '../services/api';

export default function Assessment() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [assessment, setAssessment] = useState(null);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [responses, setResponses] = useState({});
  const [participantName, setParticipantName] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const fetchAssessment = async () => {
      try {
        const assessments = await getAssessments();
        const found = assessments.find(a => a.id === parseInt(id));
        if (found) {
          setAssessment(found);
        } else {
          setError('Evaluación no encontrada');
        }
      } catch (err) {
        setError(err.message || 'Error al cargar la evaluación');
      } finally {
        setLoading(false);
      }
    };

    fetchAssessment();
  }, [id]);

  const handleAnswer = (answer) => {
    setResponses(prev => ({
      ...prev,
      [currentQuestion]: answer
    }));
  };

  const handleNext = () => {
    if (currentQuestion < assessment.questions.length - 1) {
      setCurrentQuestion(prev => prev + 1);
    }
  };

  const handlePrevious = () => {
    if (currentQuestion > 0) {
      setCurrentQuestion(prev => prev - 1);
    }
  };

  const handleSubmit = async () => {
    if (!participantName.trim()) {
      setError('Por favor ingresa tu nombre');
      return;
    }

    if (Object.keys(responses).length !== assessment.questions.length) {
      setError('Por favor responde todas las preguntas');
      return;
    }

    setSaving(true);
    try {
      await saveProgress(assessment.id, 1, {
        participant_name: participantName,
        responses,
        completed: true
      });
      navigate('/results');
    } catch (err) {
      setError(err.message || 'Error al enviar la evaluación');
    } finally {
      setSaving(false);
    }
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
      <Container maxWidth="md" sx={{ mt: 4 }}>
        <Alert severity="error">{error}</Alert>
      </Container>
    );
  }

  if (!assessment) {
    return (
      <Container maxWidth="md" sx={{ mt: 4 }}>
        <Alert severity="error">Evaluación no encontrada</Alert>
      </Container>
    );
  }

  const currentQ = assessment.questions[currentQuestion];

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h4" gutterBottom>
          {assessment.title}
        </Typography>
        
        <TextField
          fullWidth
          label="Tu Nombre"
          value={participantName}
          onChange={(e) => setParticipantName(e.target.value)}
          margin="normal"
          required
          error={!participantName && Object.keys(responses).length > 0}
          helperText={!participantName && Object.keys(responses).length > 0 ? 'El nombre es requerido' : ''}
        />

        <Box sx={{ my: 4 }}>
          <Stepper activeStep={currentQuestion} alternativeLabel>
            {assessment.questions.map((_, index) => (
              <Step key={index}>
                <StepLabel></StepLabel>
              </Step>
            ))}
          </Stepper>
        </Box>

        <Box sx={{ my: 4 }}>
          <Typography variant="h6" gutterBottom>
            Pregunta {currentQuestion + 1} de {assessment.questions.length}
          </Typography>
          <Typography variant="body1" gutterBottom>
            {currentQ.content}
          </Typography>

          <RadioGroup
            value={responses[currentQuestion] || ''}
            onChange={(e) => handleAnswer(e.target.value)}
          >
            {currentQ.options.map((option, index) => (
              <FormControlLabel
                key={index}
                value={option}
                control={<Radio />}
                label={option}
              />
            ))}
          </RadioGroup>
        </Box>

        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
          <Button
            onClick={handlePrevious}
            disabled={currentQuestion === 0}
            variant="outlined"
          >
            Anterior
          </Button>
          
          {currentQuestion < assessment.questions.length - 1 ? (
            <Button
              onClick={handleNext}
              variant="contained"
              disabled={!responses[currentQuestion]}
            >
              Siguiente
            </Button>
          ) : (
            <Button
              onClick={handleSubmit}
              variant="contained"
              color="primary"
              disabled={
                saving ||
                !participantName ||
                Object.keys(responses).length !== assessment.questions.length
              }
            >
              {saving ? <CircularProgress size={24} /> : 'Enviar'}
            </Button>
          )}
        </Box>
      </Paper>
    </Container>
  );
}
