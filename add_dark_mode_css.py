#!/usr/bin/env python3
"""
Script para agregar overrides de dark mode a clases CSS
"""

import re

# Leer archivo
with open('templates/coachee_dashboard.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Clases que necesitan dark mode override
css_classes_to_fix = [
    ('content-title', 2776, 2777),
    ('content-info-text', 4237, 4238),
    ('content-meta', 4689, 4690),
    ('task-title', 4731, 4732),
    ('tasks-header', 4763, 4764),
    ('dropdown-item', 5188, 5189),
    ('dropdown-item', 5202, 5203),
    ('dropdown-item', 5226, 5227),
    ('stats-label', 5246, 5247),
    ('calendar-header-title', 8668, 8669)
]

changes_made = 0

for class_name, block_start, color_line in css_classes_to_fix:
    # Buscar el cierre del bloque CSS (siguiente })
    closing_brace = None
    for i in range(color_line, min(color_line + 20, len(lines))):
        if lines[i].strip() == '}':
            closing_brace = i
            break
    
    if not closing_brace:
        print(f"⚠️ No se encontró cierre para {class_name}")
        continue
    
    # Verificar si ya tiene dark mode override
    already_has_dark = False
    for i in range(closing_brace, min(closing_brace + 10, len(lines))):
        if f'[data-theme="dark"] .{class_name}' in lines[i]:
            already_has_dark = True
            break
    
    if already_has_dark:
        print(f"✓ {class_name} ya tiene dark mode")
        continue
    
    # Agregar override justo después del cierre
    indent = '        '
    dark_override = f'\n{indent}[data-theme="dark"] .{class_name} {{\n{indent}    color: #f1f5f9 !important;\n{indent}}}\n'
    
    lines.insert(closing_brace + 1, dark_override)
    changes_made += 1
    print(f"✅ Agregado dark mode para .{class_name}")

# Guardar resultado
with open('templates/coachee_dashboard.html', 'w', encoding='utf-8') as f:
    f.writelines(lines)

print(f"\n📊 Total: {changes_made} clases CSS actualizadas con dark mode")
