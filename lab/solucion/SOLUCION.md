# Solución — Security Code Review Lab

> **INSTRUCTOR ONLY** — No compartir con estudiantes antes de la entrega.

---

## Mapa de vulnerabilidades

| # | Archivo | Línea | CWE | Severidad |
|---|---|---|---|---|
| V1 | `app/backend/app.py` | ~31–34 | CWE-89 SQL Injection | CRITICAL |
| V2 | `app/backend/app.py` | ~46–49 | CWE-20 Missing Input Validation | HIGH |
| V3 | `app/frontend/index.html` | ~71–72 | CWE-922 / CWE-312 Insecure Storage | HIGH |
| V4 | `app/backend/app.py` + `index.html` | ~61–64 / ~88 | CWE-602 / CWE-285 Broken Access Control | CRITICAL |

---

## V1 — SQL Injection (CWE-89)

### Código vulnerable
```python
query = (
    "SELECT * FROM users WHERE username = '"
    + username
    + "' AND password = '"
    + password
    + "'"
)
cursor.execute(query)
```

### Exploit
```
username: ' OR '1'='1' --
password: cualquier_cosa
```
La query resultante autentica sin credenciales válidas.

### Código corregido
```python
user = db.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, password),
).fetchone()
```

---

## V2 — Missing Input Validation (CWE-20)

### Código vulnerable
```python
user_id = request.args.get("id")   # puede ser "abc", "1 OR 1=1", etc.
user = db.execute(
    f"SELECT id, username, email FROM users WHERE id = {user_id}"
).fetchone()
```

### Código corregido
```python
try:
    user_id = int(request.args.get("id", ""))
except (ValueError, TypeError):
    return jsonify({"error": "id must be a positive integer"}), 400

if user_id <= 0:
    return jsonify({"error": "id must be a positive integer"}), 400

user = db.execute(
    "SELECT id, username, email FROM users WHERE id = ?",
    (user_id,),
).fetchone()
```

---

## V3 — Token en localStorage (CWE-922 / CWE-312)

### Código vulnerable
```javascript
localStorage.setItem("auth_token", data.token);
```

### Por qué es peligroso
`localStorage` es accesible por cualquier script JavaScript de la misma origen.
Un ataque XSS puede leer el token con `localStorage.getItem("auth_token")` y
usurpar la sesión del usuario.

### Código corregido

**Backend** — enviar el token como cookie `HttpOnly`:
```python
from flask import make_response
response = make_response(jsonify({"role": user["role"]}))
response.set_cookie(
    "auth_token",
    token,
    httponly=True,
    secure=True,          # solo HTTPS
    samesite="Strict",
    max_age=7200,
)
return response
```

**Frontend** — eliminar el `localStorage.setItem`. El navegador maneja la
cookie automáticamente; el JS nunca necesita leer el token.

---

## V4 — Broken Access Control (CWE-602 / CWE-285)

### Código vulnerable
```python
@app.route("/api/admin/users")
def list_all_users():
    # no hay ninguna verificación de token ni de rol
    ...
```
```javascript
// solo se oculta en el frontend:
if (data.role === "admin") {
    document.getElementById("admin-section").style.display = "block";
}
```

### Código corregido

Decorador reutilizable en el backend:
```python
import functools

def require_role(*roles):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "Unauthorized"}), 401
            try:
                payload = jwt.decode(auth.split()[1], SECRET_KEY, algorithms=["HS256"])
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid token"}), 401
            if payload.get("role") not in roles:
                return jsonify({"error": "Forbidden"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/api/admin/users")
@require_role("admin")
def list_all_users():
    ...
```

El frontend puede seguir ocultando el botón, pero eso es UX, no seguridad.

---

## Respuestas a preguntas de reflexión

1. **Payload `' OR '1'='1' --`**: la query devuelve la primera fila de la tabla, dando acceso como el primer usuario registrado (normalmente el admin).

2. **localStorage vs HttpOnly cookie**: las cookies `HttpOnly` son inaccesibles para JavaScript, por lo que un XSS no puede robar el token. `localStorage` no ofrece esa protección.

3. **Autenticación vs Autorización**: autenticación verifica identidad (¿quién eres?); autorización verifica permisos (¿qué puedes hacer?). `V4` es un fallo de *autorización*: el backend no verifica si el usuario autenticado tiene el rol requerido.

4. **Detección sin código fuente**: para `V2`, enviar parámetros no numéricos y observar si hay error 500 o stack trace. Para `V4`, llamar directamente a `/api/admin/users` sin token y ver si responde 200.
