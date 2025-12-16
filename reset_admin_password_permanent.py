#!/usr/bin/env python3
"""
Script para establecer contraseña de admin y VERIFICAR que persiste
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User
from werkzeug.security import generate_password_hash
import time

def reset_admin_password():
    """Establece nueva contraseña y verifica que persiste"""
    with app.app_context():
        try:
            admin = User.query.filter_by(username='admin', role='platform_admin').first()
            
            if not admin:
                print("❌ Usuario admin no encontrado")
                return False
            
            print("=" * 80)
            print("🔧 ESTABLECER Y VERIFICAR CONTRASEÑA DE ADMIN")
            print("=" * 80)
            print(f"\n✅ Usuario admin encontrado (ID: {admin.id})")
            print(f"   Username: {admin.username}")
            print(f"   Email: {admin.email}")
            print(f"   Activo: {admin.is_active}")
            print()
            
            # Solicitar nueva contraseña
            print("📝 Ingresa la nueva contraseña:")
            new_password = input("Contraseña: ").strip()
            
            if len(new_password) < 6:
                print("❌ La contraseña debe tener al menos 6 caracteres")
                return False
            
            # Confirmar contraseña
            confirm_password = input("Confirma la contraseña: ").strip()
            
            if new_password != confirm_password:
                print("❌ Las contraseñas no coinciden")
                return False
            
            print("\n🔄 Guardando nueva contraseña...")
            print()
            
            # Mostrar hash ANTES del cambio
            old_hash = admin.password_hash
            print(f"📋 Hash ANTERIOR:")
            print(f"   Tipo: {old_hash.split(':')[0] if ':' in old_hash else 'desconocido'}")
            print(f"   Longitud: {len(old_hash)} caracteres")
            print(f"   Primeros 50: {old_hash[:50]}...")
            print()
            
            # Establecer nueva contraseña
            admin.set_password(new_password)
            
            # Forzar escritura INMEDIATA a BD
            db.session.add(admin)
            db.session.flush()
            db.session.commit()
            db.session.expire_all()
            
            # Refrescar desde BD para confirmar
            db.session.refresh(admin)
            
            # Mostrar hash DESPUÉS del cambio
            new_hash = admin.password_hash
            print(f"✅ Hash NUEVO:")
            print(f"   Tipo: {new_hash.split(':')[0] if ':' in new_hash else 'desconocido'}")
            print(f"   Longitud: {len(new_hash)} caracteres")
            print(f"   Primeros 50: {new_hash[:50]}...")
            print()
            
            # VERIFICACIÓN 1: Probar la contraseña inmediatamente
            print("🧪 VERIFICACIÓN 1: Probando contraseña inmediatamente...")
            if admin.check_password(new_password):
                print("   ✅ Contraseña funciona AHORA")
            else:
                print("   ❌ ERROR: Contraseña NO funciona inmediatamente")
                return False
            
            print()
            print("⏳ Esperando 3 segundos...")
            time.sleep(3)
            
            # VERIFICACIÓN 2: Refrescar y probar de nuevo
            print("🧪 VERIFICACIÓN 2: Refrescando desde BD y probando de nuevo...")
            db.session.expire_all()
            db.session.refresh(admin)
            
            if admin.check_password(new_password):
                print("   ✅ Contraseña funciona después de refrescar")
            else:
                print("   ❌ ERROR: Contraseña NO funciona después de refrescar")
                return False
            
            print()
            
            # VERIFICACIÓN 3: Query fresco desde BD
            print("🧪 VERIFICACIÓN 3: Query fresco desde BD y probando...")
            admin3 = User.query.filter_by(username='admin', role='platform_admin').first()
            
            if admin3 and admin3.check_password(new_password):
                print("   ✅ Contraseña funciona en query fresco")
            else:
                print("   ❌ ERROR: Contraseña NO funciona en query fresco")
                return False
            
            print()
            print("=" * 80)
            print("✅ CONTRASEÑA ESTABLECIDA Y VERIFICADA CORRECTAMENTE")
            print("=" * 80)
            print()
            print("⚠️  IMPORTANTE:")
            print("   1. Anota esta contraseña en un lugar seguro")
            print("   2. NO uses el autocompletar del navegador")
            print("   3. Escribe la contraseña manualmente al hacer login")
            print("   4. Si el problema vuelve, significa que Railway está regenerando la BD")
            print()
            print("📋 PRÓXIMOS PASOS:")
            print("   1. Intenta login AHORA en: https://instacoach.cl/admin-login")
            print("   2. Si funciona → Verifica en 1 hora si sigue funcionando")
            print("   3. Si NO funciona → Railway tiene problema de persistencia")
            print()
            
            # Guardar timestamp del cambio
            with open('last_password_change.txt', 'w') as f:
                import datetime
                f.write(f"Última cambio de contraseña: {datetime.datetime.now()}\n")
                f.write(f"Hash: {new_hash[:50]}...\n")
            
            return True
            
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = reset_admin_password()
    exit(0 if success else 1)
