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
