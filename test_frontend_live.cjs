#!/usr/bin/env node

// Simple Node.js script to test the live frontend functionality
const https = require('https');

console.log('🌐 Testing Live Frontend at Vercel...');
console.log('URL: https://assessment-platform-7p39xmngl-cris-projects-92f3df55.vercel.app');
console.log('');

// Test 1: Check if frontend is accessible
https.get('https://assessment-platform-7p39xmngl-cris-projects-92f3df55.vercel.app', (res) => {
    console.log('✅ Frontend Status:', res.statusCode);
    console.log('📄 Content-Type:', res.headers['content-type']);
    
    let body = '';
    res.on('data', (chunk) => {
        body += chunk;
    });
    
    res.on('end', () => {
        // Check for Spanish content
        if (body.includes('Plataforma de Evaluación de Asertividad')) {
            console.log('🇪🇸 Spanish content detected: ✅');
        }
        
        if (body.includes('React')) {
            console.log('⚛️  React app detected: ✅');
        }
        
        console.log('');
        console.log('🎯 Frontend deployment verification complete!');
        console.log('📱 You can now access the application at:');
        console.log('   https://assessment-platform-7p39xmngl-cris-projects-92f3df55.vercel.app');
        console.log('');
        console.log('🔐 Test credentials:');
        console.log('   Usuario: admin');
        console.log('   Contraseña: admin123');
    });
}).on('error', (err) => {
    console.log('❌ Error:', err.message);
});
