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
          setError('Invalid results format received from server');
        }
      } catch (err) {
        console.error('Error fetching results:', err);
        setError(err.message || 'Failed to load results');
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
          Assertiveness Assessment Results
        </Typography>

        {participants.length > 0 && (
          <FormControl sx={{ minWidth: 200 }}>
            <InputLabel>Filter by Participant</InputLabel>
            <Select
              value={selectedParticipant}
              onChange={(e) => setSelectedParticipant(e.target.value)}
              label="Filter by Participant"
            >
              <MenuItem value="all">All Participants</MenuItem>
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
            Completed Assessments ({results.completed.length})
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
                          Completed: {new Date(result.completed_at).toLocaleString()}
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
                          Feedback
                        </Typography>
                        <Typography>
                          {result.feedback}
                        </Typography>
                        <Box sx={{ mt: 2 }}>
                          <Typography variant="subtitle2" color="textSecondary">
                            Response Summary:
                          </Typography>
                          {Object.entries(result.responses).map(([questionId, answerIndex]) => (
                            <Typography key={questionId} variant="body2" color="textSecondary">
                              Question {questionId}: Option {parseInt(answerIndex) + 1}
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
            In Progress ({results.in_progress.length})
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
                      Participant: {result.participant_name}
                    </Typography>
                    <Typography color="textSecondary">
                      Started: {new Date(result.started_at).toLocaleString()}
                    </Typography>
                    <Typography>
                      Progress: {Math.round((Object.keys(result.responses || {}).length / 5) * 100)}%
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
          No results found
          {selectedParticipant !== 'all' && ` for ${selectedParticipant}`}.
        </Alert>
      )}
    </Container>
  );
}
