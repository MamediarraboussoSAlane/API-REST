import psycopg2
from configparser import ConfigParser

def load_config(filename='database.ini', section='postgresql'):
    """
    Charge les paramètres de configuration à partir d'un fichier INI.
    """
    parser = ConfigParser()
    parser.read(filename)

    # Obtenir les paramètres de la section spécifiée
    if parser.has_section(section):
        params = parser.items(section)
        config = {param[0]: param[1] for param in params}
    else:
        raise Exception(f'Section {section} non trouvée dans le fichier {filename}')

    return config

def get_db_connection():
    """
    Établit une connexion à la base de données PostgreSQL en utilisant psycopg2.
    """
    config = load_config()  # Charge la configuration depuis database.ini
    connection_string = (
        f"dbname={config['database']} user={config['user']} "
        f"password={config['password']} host={config['host']} "
        f"port={config['port']}"
    )
    conn = psycopg2.connect(connection_string)
    return conn

# Exemple d'utilisation
if __name__ == '__main__':
    conn = get_db_connection()
    print("Connexion établie avec succès!")
    conn.close()


