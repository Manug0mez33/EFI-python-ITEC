Instrucciones de instalacion:
    1. git clone git@github.com:Manug0mez33/EFI-python-ITEC.git
    2. cd EFI-python-ITEC
    3. python -m venv .environment
    4. source .environment/bin/activate
    5. pip install -r requirements.txt
    6. Crear la base de datos
        - mysql -u root
        - CREATE DATABASE EFI;
        - exit;
    7. flask db upgrade
    8. flask seed-db (Para la creacion de un usuario de cada rol.)
    9. flask run --reload

Archivo de prueba: test.http (Recomendada la extension REST Client para un mejor manejo)

Comentarios:

    - Documentacion Swagger/OpenAPI, Tests con cobertura>70%, y Arquitectura service-repository hechos con IA, por lo que quedaron en ramas separadas a la main para no afectar al trabajo hecho por nosotros. (documentationSwagger, testing, service-repository-test).

    - Previamente habiamos implementado APIs para la gestion de notificaciones, pero fueron descartadas por fallas en la funcionalidad.

    - Actualizamos algunos modelos y esquemas para una correcta fusion con el frontend hecho con React, a medida que se requeria, al igual que agregamos algunas APIs como por ejemplo UserStatusAPI, con el metodo PATCH para poder reactivar un usuario (solo siendo admin).

    - Agregamos al archivo app.py un decorador para ejecutar el comando "seed-db", para luego ejecutarlo por terminal con flask seed-db, asi se crearan tres usuarios de prueba, uno por cada rol.

Alumnos:
    - Falco, Juan
    - Gomez, Manuel