#!/usr/bin/env python3
"""
Script para listar todos los usuarios y sus roles
"""
from app import app, db, User

def list_all_users():
    with app.app_context():
        users = User.query.all()
        
        if not users:
            print("❌ No hay usuarios en la base de datos")
            return
        
        print(f"\n📋 Total de usuarios: {len(users)}\n")
        print("=" * 100)
        
        for user in users:
            print(f"ID: {user.id:3d} | Username: {user.username:20s} | Email: {user.email:30s} | Role: {user.role:15s} | Active: {user.active}")
        
        print("=" * 100)

if __name__ == '__main__':
    list_all_users()
