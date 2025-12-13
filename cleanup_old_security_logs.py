#!/usr/bin/env python3
"""
Script para limpieza automática de logs de seguridad antiguos.
Archiva logs de SecurityLog mayores a LOG_RETENTION_DAYS (default: 90 días)
a archivos JSON y los elimina de la base de datos para mantener el rendimiento óptimo.

Uso:
    python cleanup_old_security_logs.py [--retention-days DAYS] [--dry-run]

Opciones:
    --retention-days DAYS : Número de días a retener (default: 90)
    --dry-run            : Mostrar qué se eliminaría sin ejecutar cambios

Este script se puede ejecutar manualmente o mediante cron job.
Railway cron job sugerido: "0 2 * * 0" (Domingos 2am)
"""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta

# Configurar path para imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, SecurityLog


def archive_logs_to_json(logs, archive_dir='security_logs_archive'):
    """
    Archiva logs a archivo JSON con timestamp.
    
    Args:
        logs: Lista de SecurityLog objects
        archive_dir: Directorio donde guardar archivos (default: security_logs_archive/)
    
    Returns:
        str: Path del archivo creado
    """
    if not logs:
        return None
    
    # Crear directorio si no existe
    os.makedirs(archive_dir, exist_ok=True)
    
    # Generar nombre de archivo con timestamp
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"security_logs_archived_{timestamp}.json"
    filepath = os.path.join(archive_dir, filename)
    
    # Convertir logs a formato JSON serializable
    logs_data = []
    for log in logs:
        log_dict = {
            'id': log.id,
            'event_type': log.event_type,
            'description': log.description,
            'user_id': log.user_id,
            'username': log.username,
            'ip_address': log.ip_address,
            'user_agent': log.user_agent,
            'severity': log.severity,
            'timestamp': log.timestamp.isoformat() if log.timestamp else None
        }
        logs_data.append(log_dict)
    
    # Guardar a archivo JSON
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump({
            'archive_date': datetime.utcnow().isoformat(),
            'total_logs': len(logs_data),
            'logs': logs_data
        }, f, indent=2, ensure_ascii=False)
    
    return filepath


def cleanup_old_security_logs(retention_days=90, dry_run=False):
    """
    Limpia logs de seguridad más antiguos que retention_days.
    
    Args:
        retention_days (int): Número de días de logs a retener (default: 90)
        dry_run (bool): Si True, solo muestra lo que se eliminaría sin ejecutar
    
    Returns:
        dict: Estadísticas de la operación
    """
    with app.app_context():
        # Calcular fecha límite (UTC)
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        print(f"🔍 Buscando logs de seguridad anteriores a {cutoff_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print(f"   (Retención: {retention_days} días)")
        
        # Buscar logs antiguos
        old_logs = SecurityLog.query.filter(
            SecurityLog.timestamp < cutoff_date
        ).all()
        
        total_logs = len(old_logs)
        
        if total_logs == 0:
            print("✅ No hay logs antiguos para eliminar")
            return {
                'success': True,
                'total_found': 0,
                'archived': 0,
                'deleted': 0,
                'archive_file': None
            }
        
        print(f"📊 Encontrados {total_logs} logs para archivar y eliminar")
        
        if dry_run:
            print("⚠️  DRY RUN - No se realizarán cambios")
            print(f"   Se archivarían {total_logs} logs a JSON")
            print(f"   Se eliminarían {total_logs} registros de la base de datos")
            return {
                'success': True,
                'dry_run': True,
                'total_found': total_logs,
                'archived': 0,
                'deleted': 0,
                'archive_file': None
            }
        
        # Archivar logs a JSON
        print("💾 Archivando logs a JSON...")
        archive_file = archive_logs_to_json(old_logs)
        
        if archive_file:
            print(f"✅ Logs archivados en: {archive_file}")
        else:
            print("⚠️  No se pudo crear archivo de archivo")
            return {
                'success': False,
                'error': 'Failed to create archive file',
                'total_found': total_logs
            }
        
        # Eliminar logs de la base de datos
        print("🗑️  Eliminando logs de la base de datos...")
        deleted_count = 0
        
        try:
            for log in old_logs:
                db.session.delete(log)
                deleted_count += 1
            
            db.session.commit()
            print(f"✅ Eliminados {deleted_count} logs de la base de datos")
            
            return {
                'success': True,
                'total_found': total_logs,
                'archived': total_logs,
                'deleted': deleted_count,
                'archive_file': archive_file
            }
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error al eliminar logs: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'total_found': total_logs,
                'archived': total_logs,
                'deleted': 0,
                'archive_file': archive_file
            }


def main():
    """Función principal con argumentos CLI."""
    parser = argparse.ArgumentParser(
        description='Limpia logs de seguridad antiguos archivándolos a JSON'
    )
    parser.add_argument(
        '--retention-days',
        type=int,
        default=int(os.environ.get('LOG_RETENTION_DAYS', 90)),
        help='Días de logs a retener (default: 90 o LOG_RETENTION_DAYS)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Modo simulación: muestra qué se eliminaría sin ejecutar cambios'
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("🧹 LIMPIEZA DE LOGS DE SEGURIDAD ANTIGUOS")
    print("=" * 70)
    print(f"Fecha de ejecución: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"Retención configurada: {args.retention_days} días")
    print(f"Modo: {'DRY RUN (simulación)' if args.dry_run else 'EJECUCIÓN REAL'}")
    print("=" * 70)
    print()
    
    # Ejecutar limpieza
    result = cleanup_old_security_logs(
        retention_days=args.retention_days,
        dry_run=args.dry_run
    )
    
    print()
    print("=" * 70)
    print("📈 RESUMEN DE LA OPERACIÓN")
    print("=" * 70)
    
    if result['success']:
        print(f"✅ Operación completada exitosamente")
        print(f"   Logs encontrados: {result['total_found']}")
        print(f"   Logs archivados: {result.get('archived', 0)}")
        print(f"   Logs eliminados de DB: {result.get('deleted', 0)}")
        
        if result.get('archive_file'):
            print(f"   Archivo generado: {result['archive_file']}")
        
        if result.get('dry_run'):
            print()
            print("⚠️  Recuerda: Esto fue una simulación (--dry-run)")
            print("   Para ejecutar realmente, ejecuta sin --dry-run")
    else:
        print(f"❌ Error en la operación")
        print(f"   {result.get('error', 'Unknown error')}")
        sys.exit(1)
    
    print("=" * 70)


if __name__ == '__main__':
    main()
