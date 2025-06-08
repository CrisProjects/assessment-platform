// Simple test to verify frontend API connectivity
// Run this in the browser console on the Vercel frontend

console.log('🧪 Testing Frontend API Connectivity');

// Check the API URL being used
const apiUrl = import.meta?.env?.VITE_API_URL || "https://assessment-platform-1nuo.onrender.com";
console.log('API URL:', apiUrl);

// Test login function
async function testLogin() {
    try {
        console.log('🔐 Testing login...');
        
        const response = await fetch(`${apiUrl}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                username: 'admin',
                password: 'admin123'
            })
        });

        console.log('Response status:', response.status);
        const data = await response.json();
        console.log('Response data:', data);

        if (data.success) {
            console.log('✅ Login successful!');
        } else {
            console.log('❌ Login failed:', data.error);
        }
    } catch (error) {
        console.error('❌ Login error:', error);
    }
}

// Run the test
testLogin();
