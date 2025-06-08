import React, { useState } from 'react';

const TestPage = () => {
  const [results, setResults] = useState({});
  const [loading, setLoading] = useState(false);

  const API_URL = import.meta.env.VITE_API_URL || "https://assessment-platform-1nuo.onrender.com";

  const testBackendConnection = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/test/status`);
      const data = await response.json();
      setResults(prev => ({
        ...prev,
        status: { success: true, data }
      }));
    } catch (error) {
      setResults(prev => ({
        ...prev,
        status: { success: false, error: error.message }
      }));
    }
    setLoading(false);
  };

  const testLoginWithoutAuth = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/test/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: 'test_user',
          password: 'any_password'
        })
      });
      const data = await response.json();
      setResults(prev => ({
        ...prev,
        login: { success: true, data }
      }));
    } catch (error) {
      setResults(prev => ({
        ...prev,
        login: { success: false, error: error.message }
      }));
    }
    setLoading(false);
  };

  const testDashboard = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/test/dashboard`);
      const data = await response.json();
      setResults(prev => ({
        ...prev,
        dashboard: { success: true, data }
      }));
    } catch (error) {
      setResults(prev => ({
        ...prev,
        dashboard: { success: false, error: error.message }
      }));
    }
    setLoading(false);
  };

  const runAllTests = async () => {
    setResults({});
    await testBackendConnection();
    await testLoginWithoutAuth();
    await testDashboard();
  };

  return (
    <div className="container mx-auto p-6">
      <div className="bg-yellow-100 border-l-4 border-yellow-500 p-4 mb-6">
        <h1 className="text-2xl font-bold text-yellow-800 mb-2">
          🔧 Página de Pruebas Sin Autenticación
        </h1>
        <p className="text-yellow-700">
          Esta página prueba la conectividad entre frontend y backend sin requerir credenciales.
        </p>
        <p className="text-sm text-yellow-600 mt-2">
          <strong>Backend URL:</strong> {API_URL}
        </p>
      </div>

      <div className="grid gap-4 mb-6">
        <button
          onClick={testBackendConnection}
          disabled={loading}
          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded disabled:opacity-50"
        >
          🔌 Probar Conexión Backend
        </button>

        <button
          onClick={testLoginWithoutAuth}
          disabled={loading}
          className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded disabled:opacity-50"
        >
          🔓 Probar Login Sin Autenticación
        </button>

        <button
          onClick={testDashboard}
          disabled={loading}
          className="bg-purple-500 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded disabled:opacity-50"
        >
          📊 Probar Dashboard Sin Autenticación
        </button>

        <button
          onClick={runAllTests}
          disabled={loading}
          className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded disabled:opacity-50"
        >
          🚀 Ejecutar Todas las Pruebas
        </button>
      </div>

      {loading && (
        <div className="bg-blue-100 border border-blue-400 text-blue-700 px-4 py-3 rounded mb-4">
          ⏳ Ejecutando prueba...
        </div>
      )}

      <div className="space-y-4">
        {Object.entries(results).map(([test, result]) => (
          <div
            key={test}
            className={`p-4 rounded border ${
              result.success
                ? 'bg-green-100 border-green-400 text-green-700'
                : 'bg-red-100 border-red-400 text-red-700'
            }`}
          >
            <h3 className="font-bold capitalize mb-2">
              {result.success ? '✅' : '❌'} Prueba: {test}
            </h3>
            
            {result.success ? (
              <div>
                <p className="mb-2">✅ Exitoso</p>
                <pre className="bg-gray-100 p-2 rounded text-sm overflow-auto">
                  {JSON.stringify(result.data, null, 2)}
                </pre>
              </div>
            ) : (
              <div>
                <p className="mb-2">❌ Error: {result.error}</p>
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="mt-8 bg-gray-100 p-4 rounded">
        <h3 className="font-bold mb-2">📋 Instrucciones:</h3>
        <ol className="list-decimal list-inside space-y-1 text-sm">
          <li>Ejecuta "Probar Conexión Backend" para verificar que el backend responde</li>
          <li>Ejecuta "Probar Login Sin Autenticación" para verificar que los endpoints funcionan</li>
          <li>Ejecuta "Probar Dashboard Sin Autenticación" para verificar el flujo completo</li>
          <li>Si todas las pruebas pasan, el problema está en la autenticación específicamente</li>
          <li>Si alguna prueba falla, el problema está en la conectividad o configuración</li>
        </ol>
      </div>
    </div>
  );
};

export default TestPage;
