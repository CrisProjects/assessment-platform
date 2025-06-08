import { useState } from 'react'
import { Routes, Route, Navigate, Link } from 'react-router-dom'
import { ThemeProvider, createTheme } from '@mui/material/styles'
import { CssBaseline, AppBar, Toolbar, Typography, Box, Button } from '@mui/material'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Assessment from './pages/Assessment'
import Results from './pages/Results'
import TestPage from './pages/TestPage'

const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
})

function App() {
  const [user, setUser] = useState(null)

  const handleLogin = (userData) => {
    setUser(userData)
  }

  const handleLogout = () => {
    setUser(null)
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box sx={{ flexGrow: 1 }}>
        <AppBar position="static">
          <Toolbar>
            <Typography 
              variant="h6" 
              component={Link} 
              to="/" 
              sx={{ 
                flexGrow: 1, 
                textDecoration: 'none', 
                color: 'inherit' 
              }}
            >
              Plataforma de Evaluación de Asertividad
            </Typography>
            
            {/* Botón de pruebas siempre visible */}
            <Button 
              color="inherit" 
              component={Link} 
              to="/test"
              sx={{ mx: 1, backgroundColor: 'rgba(255,255,255,0.1)' }}
            >
              🔧 Pruebas
            </Button>
            
            {user && (
              <>
                <Button 
                  color="inherit" 
                  component={Link} 
                  to="/dashboard"
                  sx={{ mx: 1 }}
                >
                  Panel de Control
                </Button>
                <Button 
                  color="inherit" 
                  component={Link} 
                  to="/results"
                  sx={{ mx: 1 }}
                >
                  Resultados
                </Button>
                <Typography variant="body1" sx={{ mx: 2 }}>
                  Bienvenido, {user.username}
                </Typography>
                <Button color="inherit" onClick={handleLogout}>
                  Cerrar Sesión
                </Button>
              </>
            )}
          </Toolbar>
        </AppBar>

        <Routes>
          <Route
            path="/"
            element={
              user ? (
                <Navigate to="/dashboard" replace />
              ) : (
                <Login onLogin={handleLogin} />
              )
            }
          />
          <Route
            path="/dashboard"
            element={user ? <Dashboard /> : <Navigate to="/" replace />}
          />
          <Route
            path="/assessment/:id"
            element={user ? <Assessment /> : <Navigate to="/" replace />}
          />
          <Route
            path="/results"
            element={user ? <Results /> : <Navigate to="/" replace />}
          />
          <Route
            path="/test"
            element={<TestPage />}
          />
        </Routes>
      </Box>
    </ThemeProvider>
  )
}

export default App
