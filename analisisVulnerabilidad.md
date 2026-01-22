# Análisis de Vulnerabilidad: SQL Injection (GET/Search) en bWAPP
# Índice 📑

- [1. Elección del reto](#1-elección-del-reto) 🔍  
- [2. Demostración paso a paso](#2-demostración-paso-a-paso) 🧪  
  - [2.1 Funcionamiento normal](#21-funcionamiento-normal-uso-legítimo) ✅  
  - [2.2 Comprobación de vulnerabilidad](#22-comprobación-de-la-vulnerabilidad) ⚠️  
  - [2.3 Explotación exitosa](#23-explotación-exitosa-de-la-inyección) 💥  
  - [2.4 Observación de parámetros y método HTTP](#24-observación-de-parámetros-y-método-http) 🌐  
- [3. Localizar PHP en el contenedor](#3-localizar-php-en-el-contenedor) 🐳  
  - [3.1 Acceso al contenedor](#31-acceso-al-contenedor-bwapp)  
  - [3.2 Localización del archivo vulnerable](#32-localización-del-archivo-vulnerable)  
- [4. Análisis del código y niveles de seguridad](#4-análisis-del-código-vulnerable-y-gestión-de-niveles-de-seguridad) 🔬  
  - [4.1 Control de niveles (security_level_check.php)](#41-cómo-bwapp-controla-los-niveles-de-seguridad-security_level_checkphp)  
  - [4.2 Función sqli() y niveles](#42-cómo-se-aplica-el-nivel-de-seguridad-al-input-función-sqli-en-sqli_1php)  
- [5. Conclusión y mitigaciones](#5-conclusión-y-recomendaciones) 📝

## 1. Elección del reto
Voy a analizar una vulnerabilidad en la máquina bWAPP, en concreto *** SQL Injection (GET/Search)***
Se muestra una pantalla como esta
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img1.png)

El código vulnerable se encuentra en el archivo **`sqli_1.php`**, visible en la URL:
![url fichero sqli](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img2.png)
---

## 2.Demostración paso a paso
### 2.1 Funcionamiento normal (uso legítimo)
Introduzco un término de búsqueda normal, por ejemplo **"iron"** o **"iron man"**, y se muestran solo las películas que coinciden parcialmente con el título.
![correcto funcionamiento](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img3.png)
### 2.2 Comprobación de la vulnerabilidad
Introduzco un apóstrofo simple <`asd'`> para intentar romper la sintaxis SQL.
Aparece un **error de MySQL**, lo que confirma que el input del usuario se concatena directamente en la consulta sin sanitización.
![comprobacion](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img4.png)
### 2.3. Explotación exitosa de la inyección
Utilizo el payload clásico **`asd' OR 1='1`** (o equivalentemente **`asd' OR '1'='1`**).
Resultado: **se muestran TODAS las películas** de la base de datos, ignorando el filtro de título.
![Explotación SQLi - todas las películas listadas](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img5.png)
### 2.4. Observación de parámetros y método HTTP
La petición utiliza método **GET**, por lo que el parámetro vulnerable (`title`) aparece directamente en la URL:
![URL con payload inyectado - método GET](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img6.png)
---

## 3. Localizar PHP en el contenedor
### 3.1 Acceso al contenedor bWAPP
Identifico el contenedor haciendo uso del comando 
```bash
docker ps 
```
![encontrar docker bwapp](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img7.png)
Ejecuto los comandos para entrar en el contenedor y cambiarme al directorio /var/www/HTML
```bash
Docker exec -it bwapp /bin/bash
cd /var/www/html
```
![ejecucion bwapp](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img8.png)
### 3.2 Localización del archivovulnerable
Luego localizo el fichero sqli_1.php, por ejemplo con el comando 
```bash
ls sqli*
```
![busqueda fichero sqli_1.php](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img9.png)
Para ver el código de este fichero ejecuto 
```bash
cat sqli_1.php
```
![cat al fichero](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img10.png)
---

## 4. Análisis del código vulnerable y gestión de niveles de seguridad
El reto SQL Injection (GET/Search) está implementado en el archivo **sqli_1.php**.

### 4.1. Cómo bWAPP controla los niveles de seguridad (security_level_check.php)

Antes de que cualquier reto se ejecute, bWAPP incluye el archivo `security_level_check.php`. Este script comprueba dos cosas principales:

+ Si la cookie `security_level` está definida.
+ Si la IP del usuario está autorizada (en entornos de prueba suele ser localhost o un rango local).

Si alguna de las dos condiciones falla, redirige a `security_level_set.php` para forzar la configuración.

**Captura del contenido de security_level_check.php**  
![captura de secutity level_check.php](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img11.png)

En esta captura se observa:
- Include de `admin/settings.php` (donde probablemente están definidas constantes como AIM_IPS o AIM_subnet).
- Cálculo de rangos de IPs permitidas usando ip2long, explode y bucles.
- Condición final con `if(!isset($_COOKIE["security_level"]) || !in_array(...))` que hace el redirect si algo no cuadra.

Esto explica por qué, al entrar en bWAPP desde localhost con la cookie seteada en "low", todo funciona sin redirecciones.

### 4.2. Cómo se aplica el nivel de seguridad al input del usuario (función sqli() en sqli_1.php)

Una vez que el nivel está validado, el archivo `sqli_1.php` define la función `sqli($data)` que decide qué hacer con el input del usuario (en este caso, el parámetro `title`).

**Captura de la función sqli($data) en sqli_1.php**  
![captura sqli_1.php](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img12.png)

Código:

```php
function sqli($data) {
    switch($_COOKIE["security_level"]) {
        case "0":   // Low
            $data = no_check($data);
            break;
        case "1":   // Medium
            $data = sqli_check_1($data);
            break;
        case "2":   // High
            $data = sqli_check_2($data);
            break;
        default:    // Impossible u otros
            $data = no_check($data);
            break;
    }
    return $data;
}
Explicación por nivel (en el que trabajamos: Low)
```
+ Low (case "0"): Llama a no_check($data) → no hace absolutamente nada. El input (title) llega limpio y sin filtrar a la consulta SQL → vulnerable a payloads como ' OR 1='1.
+ Medium (case "1"): Usa sqli_check_1($data) → aplica filtros básicos (elimina apóstrofos, palabras como OR, etc.). Algunos payloads simples fallan.
+ High (case "2"): Usa sqli_check_2($data) → filtros más estrictos. Mucho más difícil explotar.
Impossible: Aunque el switch usa no_check por defecto, en nivel Impossible el propio reto cambia la lógica (usa consultas preparadas en lugar de concatenación), por lo que la inyección ya no funciona.

---
Gracias a este diseño, bWAPP permite practicar la misma vulnerabilidad (SQL Injection) en diferentes escenarios: desde un entorno totalmente inseguro (Low), pasando por filtros intermedios (Medium y High), hasta un contexto en el que la vulnerabilidad debería estar corregida (Impossible). Esto ayuda a entender cómo influyen las medidas de validación y sanitización del input en la explotación real de la aplicación.