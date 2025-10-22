# Configuración de AWS S3 para Almacenamiento de Documentos

## ¿Por qué necesitamos AWS S3?

Railway y otros servicios de hosting similares tienen un **sistema de archivos efímero** (ephemeral filesystem). Esto significa que:

- ❌ Los archivos guardados localmente se **pierden** cada vez que el contenedor se reinicia
- ❌ Los archivos **no persisten** entre despliegues
- ❌ No es posible almacenar archivos subidos por usuarios de forma permanente

**Solución: AWS S3** - Servicio de almacenamiento en la nube de Amazon que permite:

- ✅ Almacenamiento permanente y confiable
- ✅ Alta disponibilidad (99.99%)
- ✅ Escalabilidad automática
- ✅ URLs directas para descargar archivos
- ✅ Muy económico (primeros 5GB gratis el primer año)

## Paso 1: Crear una Cuenta de AWS

1. Ir a https://aws.amazon.com/
2. Hacer clic en "Create an AWS Account"
3. Completar el registro (requiere tarjeta de crédito, pero el tier gratuito es suficiente)
4. Verificar email y número de teléfono

## Paso 2: Crear un Bucket de S3

1. Iniciar sesión en AWS Console: https://console.aws.amazon.com/
2. Buscar "S3" en el buscador superior
3. Hacer clic en "Create bucket"
4. Configurar el bucket:
   - **Bucket name**: `assessment-platform-documents` (debe ser único globalmente)
   - **AWS Region**: `us-east-1` (o la región más cercana)
   - **Block Public Access settings**: DESMARCAR "Block all public access"
     - ⚠️ Importante: Marcar la casilla que dice "I acknowledge..."
   - Dejar el resto de opciones por defecto
5. Hacer clic en "Create bucket"

## Paso 3: Configurar Permisos del Bucket

1. Hacer clic en el bucket recién creado
2. Ir a la pestaña "Permissions"
3. En "Bucket policy", hacer clic en "Edit"
4. Pegar la siguiente política (reemplazar `assessment-platform-documents` con tu nombre de bucket):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::assessment-platform-documents/*"
        }
    ]
}
```

5. Hacer clic en "Save changes"

## Paso 4: Crear Usuario IAM y Obtener Credenciales

1. Buscar "IAM" en el buscador superior de AWS
2. En el menú lateral, hacer clic en "Users"
3. Hacer clic en "Create user"
4. Configurar usuario:
   - **User name**: `assessment-platform-uploader`
   - Hacer clic en "Next"
5. En "Permissions options", seleccionar "Attach policies directly"
6. Buscar y seleccionar `AmazonS3FullAccess`
7. Hacer clic en "Next" y luego "Create user"

### Obtener Access Keys:

1. Hacer clic en el usuario recién creado
2. Ir a la pestaña "Security credentials"
3. En "Access keys", hacer clic en "Create access key"
4. Seleccionar "Application running outside AWS"
5. Marcar la casilla de confirmación y hacer clic en "Next"
6. (Opcional) Agregar una descripción: "Assessment Platform Document Upload"
7. Hacer clic en "Create access key"
8. **⚠️ IMPORTANTE**: Copiar inmediatamente:
   - **Access key ID**: Ejemplo: `AKIAIOSFODNN7EXAMPLE`
   - **Secret access key**: Ejemplo: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
   - **NO podrás ver el Secret Key nuevamente**, guárdalo en un lugar seguro

## Paso 5: Configurar Variables de Entorno en Railway

1. Ir a tu proyecto en Railway: https://railway.app/
2. Seleccionar tu servicio
3. Ir a la pestaña "Variables"
4. Agregar las siguientes variables:

```bash
AWS_ACCESS_KEY_ID=tu_access_key_id_aqui
AWS_SECRET_ACCESS_KEY=tu_secret_access_key_aqui
AWS_S3_BUCKET=assessment-platform-documents
AWS_REGION=us-east-1
```

5. Hacer clic en "Deploy" o esperar el redespliegue automático

## Paso 6: Verificar la Configuración

Después del despliegue, verifica los logs de Railway:

1. Busca el mensaje: `✅ Cliente S3 inicializado correctamente. Bucket: assessment-platform-documents`
2. Si ves este mensaje, la configuración es correcta
3. Si ves un error, revisa las credenciales

## Costos de AWS S3

### Tier Gratuito (12 meses):
- 5 GB de almacenamiento estándar
- 20,000 solicitudes GET
- 2,000 solicitudes PUT
- 100 GB de transferencia de datos de salida

### Después del Tier Gratuito:
- Almacenamiento: ~$0.023 por GB/mes
- Solicitudes PUT: $0.005 por 1,000 solicitudes
- Solicitudes GET: $0.0004 por 1,000 solicitudes
- Transferencia de datos: Primeros 100 GB/mes gratis

**Ejemplo de costos reales:**
- 100 documentos de 1MB cada uno = 0.1 GB
- 1,000 descargas al mes
- **Costo mensual estimado: < $0.50 USD** (prácticamente gratis)

## Solución de Problemas

### Error: "Access Denied"
- Verifica que las credenciales sean correctas
- Verifica que el usuario IAM tenga permisos de S3
- Verifica que la política del bucket permita acceso público para lectura

### Error: "Bucket not found"
- Verifica que el nombre del bucket sea correcto
- Verifica que la región sea correcta
- Los nombres de bucket son globalmente únicos, asegúrate de usar el nombre exacto

### Los archivos no se suben
- Verifica los logs de Railway para ver el error exacto
- Verifica que las variables de entorno estén configuradas correctamente
- Verifica que el bucket exista y tenga los permisos correctos

### Archivos subidos pero no se pueden descargar
- Verifica que la política del bucket permita acceso público (`s3:GetObject`)
- Verifica que el dominio de Railway esté en la lista de CORS (si aplica)

## Alternativas a AWS S3

Si prefieres no usar AWS, estas son alternativas compatibles con S3:

1. **Cloudflare R2** (más económico, sin cargos de transferencia)
2. **DigitalOcean Spaces** (similar a S3, más simple)
3. **Backblaze B2** (muy económico)
4. **MinIO** (self-hosted, compatible con S3 API)

Todas estas alternativas funcionan con el código actual (solo cambia las URLs y credenciales).

## Migración de Archivos Existentes (Si aplica)

Si ya tienes archivos en el sistema local de Railway, no es posible migrarlos automáticamente. Los archivos se perderán en el próximo despliegue. Recomendamos:

1. Subir nuevamente los documentos después de configurar S3
2. O contactar a los usuarios para que vuelvan a subir sus documentos

## Seguridad

⚠️ **Nunca compartas o hagas commit de:**
- AWS Access Key ID
- AWS Secret Access Key
- Nombres de buckets privados

✅ **Buenas prácticas:**
- Usa variables de entorno para las credenciales
- Nunca las incluyas en el código
- Rota las credenciales cada 90 días
- Usa políticas de bucket restrictivas (solo permitir lo necesario)

## Soporte

Si tienes problemas con la configuración:
1. Revisa los logs de Railway
2. Verifica que todas las variables de entorno estén configuradas
3. Consulta la documentación de AWS S3: https://docs.aws.amazon.com/s3/
