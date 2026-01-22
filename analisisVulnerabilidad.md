1. Elección del reto
Voy a analizar una vulnerabilidad en la máquina bWAPP, en concreto SQL Injection (GET/Search)
Se muestra una pantalla como esta
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img1.png)

Está ejecutando la fuente en sqli_1.php
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img2.png)
**DEMOSTRACIÓN**
***
2.Probar el funcionamiento normal
Hago uso de payloads inofensivos para demostrar el problema.
***
Lo primero es por ejemplo mostrar que efectivamente muestra peliculas como "iron man"
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img3.png)
3. Comprobar si es vulnerable
Buscando en internet encuentro que por ejemplo poniendo asd' aparece un error de MySQL, indica que la consulta se está rompiendo y que puede haber SQLi
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img4.png)
4. Explotar la inyección
Ahora al introducir el payload <asd' OR 1='1> aparecen todas las películas, no solo los que coinciden con asd, eso demuestra la SQL Injection
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img5.png)
5. Observar parámetros y tipo de petición
Me fijo en la URL; es tipo ***GET***, sale lo siguiente
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img6.png)
6. Localizar PHP en el contenedor
Con el comando <Docker ps> busco cual es el contenedor de bWAPP
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img7.png)
Ejecuto los comandos 
***
Docker exec -it bwapp /bin/bash
cd /var/www/html
***
para entrar en el contenedor y cambiarme al directorio /var/www/HTML
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img8.png)
Luego localizo el fichero sqli_1.php, por ejemplo con el comando 
***
ls sqli*
***
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img9.png)
Para ver el código de este fichero ejecuto 
***
cat sqli_1.php
***
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img10.png)
## 7. Análisis del código vulnerable y gestión de niveles de seguridad

El reto SQL Injection (GET/Search) está implementado en el archivo **sqli_1.php**.

### 7.1. Cómo bWAPP controla los niveles de seguridad (security_level_check.php)

Antes de que cualquier reto se ejecute, bWAPP incluye el archivo `security_level_check.php`. Este script comprueba dos cosas principales:

- Si la cookie `security_level` está definida.
- Si la IP del usuario está autorizada (en entornos de prueba suele ser localhost o un rango local).

Si alguna de las dos condiciones falla, redirige a `security_level_set.php` para forzar la configuración.

**Captura del contenido de security_level_check.php**  
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img11.png)

En esta captura se observa:
- Include de `admin/settings.php` (donde probablemente están definidas constantes como AIM_IPS o AIM_subnet).
- Cálculo de rangos de IPs permitidas usando ip2long, explode y bucles.
- Condición final con `if(!isset($_COOKIE["security_level"]) || !in_array(...))` que hace el redirect si algo no cuadra.

Esto explica por qué, al entrar en bWAPP desde localhost con la cookie seteada en "low", todo funciona sin redirecciones.

### 7.2. Cómo se aplica el nivel de seguridad al input del usuario (función sqli() en sqli_1.php)

Una vez que el nivel está validado, el archivo `sqli_1.php` define la función `sqli($data)` que decide qué hacer con el input del usuario (en este caso, el parámetro `title`).

**Captura de la función sqli($data) en sqli_1.php**  
![Pantallazo bwap](https://raw.githubusercontent.com/vjp-naiaraAH/Actividad-Maquinas-Vulnerables-U2/refs/heads/main/images/img12.png)

Código relevante extraído:

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

+ Low (case "0"): Llama a no_check($data) → no hace absolutamente nada. El input (title) llega limpio y sin filtrar a la consulta SQL → vulnerable a payloads como ' OR 1='1.
+ Medium (case "1"): Usa sqli_check_1($data) → aplica filtros básicos (elimina apóstrofos, palabras como OR, etc.). Algunos payloads simples fallan.
+ High (case "2"): Usa sqli_check_2($data) → filtros más estrictos. Mucho más difícil explotar.
Impossible: Aunque el switch usa no_check por defecto, en nivel Impossible el propio reto cambia la lógica (usa consultas preparadas en lugar de concatenación), por lo que la inyección ya no funciona.


---
Gracias a este diseño, bWAPP permite practicar la misma vulnerabilidad (SQL Injection) en diferentes escenarios: desde un entorno totalmente inseguro (Low), pasando por filtros intermedios (Medium y High), hasta un contexto en el que la vulnerabilidad debería estar corregida (Impossible). Esto ayuda a entender cómo influyen las medidas de validación y sanitización del input en la explotación real de la aplicación.