#!/usr/bin/env python3
"""Script para reconstruir la sección Planes de Desarrollo con el modal integrado"""

with open('templates/coach_dashboard_v2.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Encontrar la sección Planes de Desarrollo
section_start = content.find('<!-- Planes de Desarrollo Module -->')
section_end = content.find('<!-- Evaluaciones Pendientes Module -->')

# Encontrar el modal createDevPlanModal
modal_start = content.find('<!-- Modal Wizard para Crear Plan de Desarrollo Personal -->')
# Encontrar el cierre del modal buscando </div></div></div> después del script
modal_temp = content[modal_start:]
# Buscar el cierre correcto: después de modal-footer
footer_pos = modal_temp.find('</div>\n            </div>\n        </div>\n    </div>\n</div>')
if footer_pos > 0:
    modal_end = modal_start + footer_pos + len('</div>\n            </div>\n        </div>\n    </div>\n</div>')
else:
    print("❌ No se encontró el final del modal")
    exit(1)

print(f"Sección encontrada: {section_start} a {section_end}")
print(f"Modal encontrado: {modal_start} a {modal_end}")
print(f"Longitud del modal: {modal_end - modal_start} caracteres")

# Extraer el contenido del modal
modal_content = content[modal_start:modal_end]

# Agregar margin-top al modal
modal_content = modal_content.replace(
    '<div class="modal-dialog modal-xl modal-dialog-scrollable">',
    '<div class="modal-dialog modal-xl modal-dialog-scrollable" style="margin-top: 5rem;">'
)

# Encontrar el punto de inserción (antes del cierre de la sección)
section_content = content[section_start:section_end]
insert_point = section_content.rfind('</div>\n            </div>')

if insert_point == -1:
    print("❌ No se encontró el punto de inserción")
    exit(1)

# Construir la nueva sección con el modal integrado
new_section = (
    section_content[:insert_point] + 
    '\n\n                ' + modal_content.replace('\n', '\n                ') + 
    '\n            ' + section_content[insert_point:]
)

# Construir el nuevo contenido del archivo
new_content = (
    content[:section_start] +
    new_section +
    content[section_end:modal_start] +
    content[modal_end:]
)

# Escribir el archivo
with open('templates/coach_dashboard_v2.html', 'w', encoding='utf-8') as f:
    f.write(new_content)

print("✅ Sección reconstruida exitosamente!")
print(f"📊 Reducción de líneas: ~{(modal_end - modal_start) // 50} líneas movidas dentro de la sección")
