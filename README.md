# Actividad Máquinas Vulnerables – Unidad 2

Práctica de explotación y análisis de **SQL Injection** en bWAPP (nivel Low).

**Objetivo:**  
Demostrar la vulnerabilidad SQL Injection (GET/Search), explotarla paso a paso, inspeccionar el código fuente y explicar los niveles de seguridad de bWAPP.

## Reto analizado
- **Aplicación:** bWAPP  
- **Vulnerabilidad:** SQL Injection (GET/Search)  
- **Archivo:** `sqli_1.php`  
- **Parámetro vulnerable:** `title` (método GET)  
- **Nivel:** Low  
- **Payload clave:** `asd' OR 1='1` → devuelve **todas** las películas

## Capturas destacadas

**Búsqueda normal**  
![Búsqueda normal](images/img3.png)

**Error de sintaxis (prueba de ruptura)**  
![Error SQL con 'asd'`](images/img4.png)

**Explotación completa**  
![Todas las películas listadas](images/img5.png)

**URL con payload inyectado**  
![URL GET con inyección](images/img6.png)

## Documentación completa
El análisis detallado (con todos los pasos, comandos Docker, código fuente y explicación de niveles Low/Medium/High/Impossible) está en:

→ **[analisisVulnerabilidad.md](./analisisVulnerabilidad.md)**

## Estructura del repositorio