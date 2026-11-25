import os
from dotenv import load_dotenv
load_dotenv()

import mysql.connector
 
def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password=os.getenv("DB_PASSWORD"),
        database="sistema_membresias"
    )
conexion = get_connection()
cursor = conexion.cursor()

#hago un select basico para ver si funciona la conexion

#Puse un registro de prueba en la tabla de membresias ((1, 'Plan Mensual', 'Acceso basico por 30 dias', Decimal('299.00'), 30, 1))

#pip