# Laboratorio: Security Code Review

**Duración estimada:** 90 minutos  
**Nivel:** Intermedio  
**Modalidad:** Individual o parejas

---

## Objetivo

Analizar un fragmento de código real de una API web Python/Flask y una interfaz HTML/JS con **4 vulnerabilidades de seguridad embebidas**. Para cada una deberás:

1. Identificar la vulnerabilidad en el código
2. Clasificarla (nombre técnico + CWE)
3. Proponer el código corregido
4. Verificar tu hallazgo con las herramientas SAST y DAST del laboratorio

---

## Entorno

### Opción A — GitHub Codespaces (recomendada)

1. Abre el repositorio en GitHub
2. Click en **Code → Open with Codespaces → New Codespace**
3. Espera que el entorno se configure (~2 min)
4. El backend se inicializa automáticamente

### Opción B — Local

```bash
# Clonar
git clone <repo-url>
cd security-lab

# Instalar dependencias
pip install -r app/backend/requirements.txt -r requirements-dev.txt

# Inicializar la base de datos
python app/backend/init_db.py

# Arrancar la API
python app/backend/app.py
```

---

## Archivos a revisar

| Archivo | Descripción |
|---|---|
| `app/backend/app.py` | API Flask — 3 vulnerabilidades |
| `app/frontend/index.html` | SPA HTML/JS — 2 vulnerabilidades (una se repite) |

> Una vulnerabilidad se manifiesta tanto en backend como en frontend.

---

## Parte 1 — Revisión Manual (45 min)

Lee los dos archivos y completa la siguiente tabla **sin usar las herramientas automatizadas todavía**:

| # | Archivo / Línea aprox. | Descripción del problema | Tipo de vulnerabilidad | CWE |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |

**Pista:** busca estas categorías

- Construcción dinámica de queries SQL
- Falta de validación de tipo/formato en parámetros de entrada
- Almacenamiento inseguro de credenciales en el cliente
- Control de acceso a recursos sensibles implementado solo en el cliente

---

## Parte 2 — Herramientas SAST (15 min)

Ejecuta el análisis estático:

```bash
bash scripts/run_sast.sh
```

1. ¿Cuántas vulnerabilidades detectó Bandit? ¿Cuáles?
2. ¿Cuántas detectó Semgrep? ¿Hay alguna que Bandit no encontró?
3. ¿Hubo alguna que **no detectó ninguna herramienta**? ¿Por qué crees que es así?

---

## Parte 3 — Herramientas DAST (15 min)

Con la API corriendo, ejecuta las pruebas dinámicas:

```bash
python scripts/run_dast.py
```

Analiza la salida:

1. ¿Qué vulnerabilidades fueron confirmadas dinámicamente?
2. Para la SQLi: ¿qué payload usó el scanner? ¿cómo funciona?
3. ¿Por qué la vulnerabilidad `V3` no puede verificarse con DAST automatizado?

---

## Parte 4 — Código Corregido (15 min)

Para cada vulnerabilidad encontrada, escribe el fragmento corregido.  
Puedes crear los archivos `app/backend/app_fixed.py` y `app/frontend/index_fixed.html`.

### Guía de corrección

| Vulnerabilidad | Herramienta/técnica correcta |
|---|---|
| SQL Injection | Queries parametrizadas (`?` placeholders) |
| Falta de validación | `int()`, validación de rango, manejo de `ValueError` |
| Token en localStorage | `HttpOnly` cookie con `Secure` y `SameSite=Strict` |
| Acceso solo en frontend | Middleware de autenticación en el servidor |

---

## Preguntas de reflexión

1. Si un atacante explotara la vulnerabilidad `V1` con el payload `' OR '1'='1' --`, ¿qué obtendría?
2. ¿Por qué guardar un JWT en `localStorage` es más peligroso que en una cookie `HttpOnly`?
3. ¿Qué diferencia hay entre autenticación y autorización? ¿Cuál de las dos falla en `V4`?
4. Un pentester tiene acceso solo a la API (sin el código fuente). ¿Cómo detectaría `V2` y `V4`?

---

## Criterios de evaluación

| Criterio | Puntos |
|---|---|
| Identificar las 4 vulnerabilidades con archivo y línea | 40 |
| Clasificación correcta (nombre + CWE) | 20 |
| Código corregido funcional para al menos 3 vulnerabilidades | 30 |
| Preguntas de reflexión | 10 |
| **Total** | **100** |
