#!/usr/bin/env python3
"""
Script para diagnosticar por qué el endpoint no devuelve evaluaciones
"""
import sys
from sqlalchemy import create_engine, text

def diagnose_railway():
    print("\n" + "="*70)
    print("🔍 DIAGNÓSTICO: ¿Por qué no se cargan evaluaciones en Railway?")
    print("="*70)
    
    database_url = input("\n📋 Pega el DATABASE_URL de Railway: ").strip()
    
    if not database_url or database_url.startswith('${{'):
        print("❌ ERROR: Necesitas el DATABASE_URL real")
        return
    
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    try:
        engine = create_engine(database_url)
        
        with engine.connect() as conn:
            print("✅ Conectado a Railway PostgreSQL\n")
            
            # 1. Verificar evaluaciones
            print("="*70)
            print("1️⃣  VERIFICANDO TABLA ASSESSMENT")
            print("="*70)
            
            result = conn.execute(text("""
                SELECT id, title, is_active, status, created_at
                FROM assessment
                ORDER BY id
            """))
            
            assessments = result.fetchall()
            print(f"\n📊 Total de filas: {len(assessments)}")
            
            if len(assessments) == 0:
                print("❌ LA TABLA ESTÁ VACÍA - Este es el problema!")
                return
            
            print("\n📋 Evaluaciones encontradas:")
            for row in assessments:
                active_emoji = "✅" if row[2] else "❌"
                print(f"   {active_emoji} ID {row[0]}: {row[1]}")
                print(f"      is_active: {row[2]}, status: {row[3]}, created_at: {row[4]}")
            
            # 2. Simular la query exacta del backend
            print("\n" + "="*70)
            print("2️⃣  SIMULANDO QUERY DEL BACKEND")
            print("="*70)
            print("\nQuery: SELECT * FROM assessment WHERE is_active = TRUE OR is_active = 1")
            
            result = conn.execute(text("""
                SELECT id, title, is_active
                FROM assessment
                WHERE is_active = TRUE OR is_active = 1
            """))
            
            active_assessments = result.fetchall()
            print(f"\n📊 Evaluaciones que el backend debería retornar: {len(active_assessments)}")
            
            if len(active_assessments) == 0:
                print("\n❌ PROBLEMA ENCONTRADO:")
                print("   La query no encuentra evaluaciones activas.")
                print("   Verifica el tipo de dato de is_active en PostgreSQL.")
                
                # Verificar el tipo de dato
                result = conn.execute(text("""
                    SELECT data_type, column_default
                    FROM information_schema.columns
                    WHERE table_name = 'assessment' AND column_name = 'is_active'
                """))
                col_info = result.fetchone()
                print(f"\n   Tipo de dato is_active: {col_info[0]}")
                print(f"   Default: {col_info[1]}")
            else:
                print("\n✅ Evaluaciones encontradas:")
                for row in active_assessments:
                    print(f"   • ID {row[0]}: {row[1]} (is_active={row[2]})")
            
            # 3. Verificar usuarios coach
            print("\n" + "="*70)
            print("3️⃣  VERIFICANDO USUARIOS COACH")
            print("="*70)
            
            result = conn.execute(text("""
                SELECT id, username, email, role
                FROM "user"
                WHERE role = 'coach'
            """))
            
            coaches = result.fetchall()
            print(f"\n📊 Coaches registrados: {len(coaches)}")
            
            if len(coaches) == 0:
                print("❌ NO HAY USUARIOS CON ROL 'coach'")
                print("   Necesitas crear un usuario coach primero.")
            else:
                print("\n👤 Coaches encontrados:")
                for row in coaches:
                    print(f"   • ID {row[0]}: {row[1]} ({row[2]}) - role: {row[3]}")
            
            # 4. Verificar preguntas
            print("\n" + "="*70)
            print("4️⃣  VERIFICANDO PREGUNTAS")
            print("="*70)
            
            result = conn.execute(text("""
                SELECT assessment_id, COUNT(*) as questions_count
                FROM question
                WHERE is_active = TRUE
                GROUP BY assessment_id
            """))
            
            questions = result.fetchall()
            print(f"\n📊 Evaluaciones con preguntas: {len(questions)}")
            
            if len(questions) == 0:
                print("⚠️  No hay preguntas activas en la tabla 'question'")
                print("   Las evaluaciones sin preguntas podrían no mostrarse.")
            else:
                print("\n📝 Conteo de preguntas por evaluación:")
                for row in questions:
                    print(f"   • Assessment ID {row[0]}: {row[1]} preguntas")
            
            # 5. Resumen y diagnóstico
            print("\n" + "="*70)
            print("📋 RESUMEN DEL DIAGNÓSTICO")
            print("="*70)
            
            print(f"\n✅ Evaluaciones en DB: {len(assessments)}")
            print(f"✅ Evaluaciones activas (query backend): {len(active_assessments)}")
            print(f"✅ Usuarios coach: {len(coaches)}")
            print(f"✅ Evaluaciones con preguntas: {len(questions)}")
            
            if len(active_assessments) > 0 and len(coaches) > 0:
                print("\n🎉 TODO PARECE CORRECTO EN LA BASE DE DATOS")
                print("\n💡 POSIBLES CAUSAS DEL PROBLEMA:")
                print("   1. El usuario NO está autenticado como coach")
                print("   2. La sesión expiró (coach_user_id no está en session)")
                print("   3. Hay un error en el decorador @coach_session_required")
                print("   4. El navegador tiene cookies bloqueadas")
                print("\n🔍 PARA VERIFICAR:")
                print("   1. Abre la consola del navegador (F12)")
                print("   2. Ve a Application → Cookies → tu dominio")
                print("   3. Busca la cookie 'session'")
                print("   4. Si no existe, el coach no está logueado")
                print("\n   O revisa los logs de Railway:")
                print("   Railway → Tu app → Deployments → Latest → Logs")
                print("   Busca el mensaje: '=== OBTENIENDO EVALUACIONES DISPONIBLES'")
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    diagnose_railway()
