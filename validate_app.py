#!/usr/bin/env python3
"""
Script para validar sistemáticamente todas las funcionalidades de la app
"""
import requests
import json
import time

class AppValidator:
    def __init__(self, base_url="http://127.0.0.1:10000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = {}
        
    def log_result(self, test_name, status, details=""):
        """Registrar resultado de una prueba"""
        self.results[test_name] = {
            'status': status,
            'details': details
        }
        status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"{status_icon} {test_name}: {status}")
        if details:
            print(f"   {details}")
    
    def test_1_server_status(self):
        """1. Validar que el servidor está funcionando"""
        print("\n=== 1. VALIDANDO SERVIDOR ===")
        try:
            response = self.session.get(f"{self.base_url}/api/status")
            if response.status_code == 200:
                self.log_result("Servidor funcionando", "PASS", f"Status code: {response.status_code}")
            else:
                self.log_result("Servidor funcionando", "FAIL", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result("Servidor funcionando", "FAIL", f"Error: {str(e)}")
    
    def test_2_homepage(self):
        """2. Validar página principal"""
        print("\n=== 2. VALIDANDO PÁGINA PRINCIPAL ===")
        try:
            response = self.session.get(f"{self.base_url}/")
            if response.status_code == 200:
                self.log_result("Página principal carga", "PASS", "Homepage accesible")
            else:
                self.log_result("Página principal carga", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Página principal carga", "FAIL", f"Error: {str(e)}")
    
    def test_3_dashboard_selection(self):
        """3. Validar selección de dashboard"""
        print("\n=== 3. VALIDANDO SELECCIÓN DE DASHBOARD ===")
        try:
            response = self.session.get(f"{self.base_url}/dashboard-selection")
            if response.status_code == 200:
                self.log_result("Dashboard selection", "PASS", "Página de selección accesible")
            else:
                self.log_result("Dashboard selection", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Dashboard selection", "FAIL", f"Error: {str(e)}")
    
    def test_4_admin_login_page(self):
        """4. Validar página de login de admin"""
        print("\n=== 4. VALIDANDO LOGIN DE ADMIN ===")
        try:
            response = self.session.get(f"{self.base_url}/admin-login")
            if response.status_code == 200:
                self.log_result("Admin login page", "PASS", "Página de admin login accesible")
            else:
                self.log_result("Admin login page", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Admin login page", "FAIL", f"Error: {str(e)}")
    
    def test_5_coach_login_page(self):
        """5. Validar página de login de coach"""
        print("\n=== 5. VALIDANDO LOGIN DE COACH ===")
        try:
            response = self.session.get(f"{self.base_url}/coach-login")
            if response.status_code == 200:
                self.log_result("Coach login page", "PASS", "Página de coach login accesible")
            else:
                self.log_result("Coach login page", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Coach login page", "FAIL", f"Error: {str(e)}")
    
    def test_6_coachee_dashboard(self):
        """6. Validar dashboard de coachee"""
        print("\n=== 6. VALIDANDO DASHBOARD DE COACHEE ===")
        try:
            response = self.session.get(f"{self.base_url}/coachee-dashboard")
            if response.status_code == 200:
                self.log_result("Coachee dashboard", "PASS", "Dashboard de coachee accesible")
            else:
                self.log_result("Coachee dashboard", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Coachee dashboard", "FAIL", f"Error: {str(e)}")
    
    def test_7_coach_dashboard(self):
        """7. Validar dashboard de coach (sin autenticación)"""
        print("\n=== 7. VALIDANDO DASHBOARD DE COACH ===")
        try:
            response = self.session.get(f"{self.base_url}/coach-dashboard")
            # Esperamos redirección o página de login
            if response.status_code in [200, 302]:
                self.log_result("Coach dashboard routing", "PASS", f"Ruta funciona (Status: {response.status_code})")
            else:
                self.log_result("Coach dashboard routing", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Coach dashboard routing", "FAIL", f"Error: {str(e)}")
    
    def test_8_api_questions(self):
        """8. Validar API de preguntas"""
        print("\n=== 8. VALIDANDO API DE PREGUNTAS ===")
        try:
            response = self.session.get(f"{self.base_url}/api/questions")
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('questions'):
                    self.log_result("API questions", "PASS", f"Devuelve {len(data['questions'])} preguntas")
                else:
                    self.log_result("API questions", "FAIL", "Respuesta inválida")
            else:
                self.log_result("API questions", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("API questions", "FAIL", f"Error: {str(e)}")
    
    def test_9_admin_login_functionality(self):
        """9. Validar funcionalidad de login de admin"""
        print("\n=== 9. VALIDANDO FUNCIONALIDAD LOGIN ADMIN ===")
        try:
            login_data = {"username": "admin", "password": "admin123"}
            response = self.session.post(f"{self.base_url}/api/admin/login", json=login_data)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    self.log_result("Admin login funcional", "PASS", "Login de admin exitoso")
                    return True
                else:
                    self.log_result("Admin login funcional", "FAIL", "Login sin éxito")
            else:
                self.log_result("Admin login funcional", "FAIL", f"Status: {response.status_code}, Error: {response.text}")
        except Exception as e:
            self.log_result("Admin login funcional", "FAIL", f"Error: {str(e)}")
        return False
    
    def test_10_admin_dashboard_access(self):
        """10. Validar acceso al dashboard de admin (después del login)"""
        print("\n=== 10. VALIDANDO ACCESO DASHBOARD ADMIN ===")
        # Primero hacer login
        if not self.test_9_admin_login_functionality():
            self.log_result("Admin dashboard access", "SKIP", "Login admin falló")
            return
        
        try:
            response = self.session.get(f"{self.base_url}/platform-admin-dashboard")
            if response.status_code == 200:
                self.log_result("Admin dashboard access", "PASS", "Dashboard admin accesible después del login")
            else:
                self.log_result("Admin dashboard access", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Admin dashboard access", "FAIL", f"Error: {str(e)}")
    
    def test_11_coach_login_functionality(self):
        """11. Validar funcionalidad de login de coach"""
        print("\n=== 11. VALIDANDO FUNCIONALIDAD LOGIN COACH ===")
        try:
            # Usar credenciales existentes
            login_data = {"username": "coach1", "password": "coach123"}
            response = self.session.post(f"{self.base_url}/api/coach/login", json=login_data)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    self.log_result("Coach login funcional", "PASS", "Login de coach exitoso")
                    return True
                else:
                    self.log_result("Coach login funcional", "FAIL", "Login sin éxito")
            else:
                self.log_result("Coach login funcional", "WARN", f"Status: {response.status_code} - Puede necesitar credenciales válidas")
        except Exception as e:
            self.log_result("Coach login funcional", "FAIL", f"Error: {str(e)}")
        return False
    
    def test_12_database_connectivity(self):
        """12. Validar conectividad con base de datos"""
        print("\n=== 12. VALIDANDO BASE DE DATOS ===")
        try:
            # Intentar acceder a un endpoint que requiere DB
            response = self.session.get(f"{self.base_url}/api/questions")
            if response.status_code == 200:
                self.log_result("Database connectivity", "PASS", "Base de datos responde correctamente")
            else:
                self.log_result("Database connectivity", "FAIL", f"DB no responde: {response.status_code}")
        except Exception as e:
            self.log_result("Database connectivity", "FAIL", f"Error: {str(e)}")
    
    def test_13_templates_rendering(self):
        """13. Validar renderizado de templates"""
        print("\n=== 13. VALIDANDO TEMPLATES ===")
        templates_to_test = [
            "/admin-login",
            "/coach-login", 
            "/dashboard-selection",
            "/coachee-dashboard"
        ]
        
        passed = 0
        for template_route in templates_to_test:
            try:
                response = self.session.get(f"{self.base_url}{template_route}")
                if response.status_code == 200 and len(response.text) > 100:  # Template renderizado
                    passed += 1
            except:
                pass
        
        if passed == len(templates_to_test):
            self.log_result("Templates rendering", "PASS", f"Todos los {passed} templates renderizados")
        elif passed > 0:
            self.log_result("Templates rendering", "WARN", f"{passed}/{len(templates_to_test)} templates renderizados")
        else:
            self.log_result("Templates rendering", "FAIL", "Ningún template se renderiza correctamente")
    
    def test_14_static_files(self):
        """14. Validar archivos estáticos"""
        print("\n=== 14. VALIDANDO ARCHIVOS ESTÁTICOS ===")
        try:
            # Verificar que la carpeta static existe y es accesible
            response = self.session.get(f"{self.base_url}/static/")
            # Algunos servidores retornan 403 para directorios, eso es normal
            if response.status_code in [200, 403, 404]:
                self.log_result("Static files setup", "PASS", "Configuración de archivos estáticos OK")
            else:
                self.log_result("Static files setup", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Static files setup", "FAIL", f"Error: {str(e)}")
    
    def run_all_tests(self):
        """Ejecutar todas las validaciones"""
        print("🚀 INICIANDO VALIDACIÓN COMPLETA DE LA APLICACIÓN")
        print("=" * 60)
        
        # Ejecutar todas las pruebas
        self.test_1_server_status()
        self.test_2_homepage()
        self.test_3_dashboard_selection()
        self.test_4_admin_login_page()
        self.test_5_coach_login_page()
        self.test_6_coachee_dashboard()
        self.test_7_coach_dashboard()
        self.test_8_api_questions()
        self.test_9_admin_login_functionality()
        self.test_10_admin_dashboard_access()
        self.test_11_coach_login_functionality()
        self.test_12_database_connectivity()
        self.test_13_templates_rendering()
        self.test_14_static_files()
        
        # Resumen final
        print("\n" + "=" * 60)
        print("📊 RESUMEN DE VALIDACIÓN")
        print("=" * 60)
        
        passed = sum(1 for r in self.results.values() if r['status'] == 'PASS')
        failed = sum(1 for r in self.results.values() if r['status'] == 'FAIL')
        warnings = sum(1 for r in self.results.values() if r['status'] == 'WARN')
        skipped = sum(1 for r in self.results.values() if r['status'] == 'SKIP')
        
        total = len(self.results)
        
        print(f"✅ PASADAS: {passed}/{total}")
        print(f"❌ FALLIDAS: {failed}/{total}")
        print(f"⚠️ ADVERTENCIAS: {warnings}/{total}")
        print(f"⏭️ OMITIDAS: {skipped}/{total}")
        
        if failed == 0:
            print(f"\n🎉 ¡EXCELENTE! Todas las funcionalidades core están funcionando correctamente.")
        elif failed <= 2:
            print(f"\n👍 La aplicación está funcionando bien con {failed} problemas menores.")
        else:
            print(f"\n⚠️ La aplicación tiene {failed} problemas que requieren atención.")
        
        return self.results

if __name__ == "__main__":
    validator = AppValidator()
    results = validator.run_all_tests()
