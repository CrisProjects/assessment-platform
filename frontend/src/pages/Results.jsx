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
} from '@mui/material';
import { getResults } from '../services/api';

export default function Results() {
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedParticipant, setSelectedParticipant] = useState('all');
  const [participants, setParticipants] = useState([]);

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const data = await getResults(1, selectedParticipant);
        setResults(data);
        
        // Extract unique participants
        const participantSet = new Set();
        [...data.completed, ...data.in_progress].forEach(result => {
          participantSet.add(result.participant_name);
        });
        setParticipants(Array.from(participantSet));
      } catch (err) {
        setError(err.message || 'Failed to load results');
      } finally {
        setLoading(false);
      }
    };

    fetchResults();
  }, [selectedParticipant]);

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
    <Container maxWidth="lg" sx={{ mt: 4 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          Assessment Results
        </Typography>

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
      </Box>

      {results.in_progress.length > 0 && (
        <Box sx={{ mb: 4 }}>
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
                      Progress: {Math.round((Object.keys(result.responses).length / 10) * 100)}%
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {results.completed.length > 0 && (
        <Box>
          <Typography variant="h5" gutterBottom>
            Completed ({results.completed.length})
          </Typography>
          <Grid container spacing={3}>
            {results.completed.map((result) => (
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
                      Completed: {new Date(result.completed_at).toLocaleString()}
                    </Typography>
                    <Typography>
                      Score: {result.score ? `${result.score.toFixed(1)}%` : 'N/A'}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}

      {results.completed.length === 0 && results.in_progress.length === 0 && (
        <Alert severity="info">
          No results found
          {selectedParticipant !== 'all' && ` for ${selectedParticipant}`}.
        </Alert>
      )}
    </Container>
  );
}
