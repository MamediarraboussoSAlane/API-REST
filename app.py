from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import psycopg2
from configparser import ConfigParser
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
import os

# Charger les variables d'environnement depuis le fichier .env
load_dotenv()

app = Flask(__name__)

# Configuration de Flask-JWT-Extended
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'vous-devriez-changer-cela-en-production')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')  # Clé secrète pour JWT
app.config['JWT_TOKEN_LOCATION'] = ['headers']  # Emplacement du token dans la requête

jwt = JWTManager(app)

def load_config(filename='database.ini', section='postgresql'):
    """Charge les paramètres de configuration à partir d'un fichier INI."""
    parser = ConfigParser()
    parser.read(filename)

    if parser.has_section(section):
        params = parser.items(section)
        config = {param[0]: param[1] for param in params}
    else:
        raise Exception(f'Section {section} non trouvée dans le fichier {filename}')

    return config

def get_db_connection():
    """Établit une connexion à la base de données PostgreSQL en utilisant psycopg2."""
    config = load_config()
    connection_string = (
        f"dbname={config['database']} user={config['user']} "
        f"password={config['password']} host={config['host']} "
        f"port={config['port']}"
    )
    conn = psycopg2.connect(connection_string)
    return conn

@app.route('/register', methods=['POST'])
def register():
    """Route pour l'inscription d'un utilisateur."""
    data = request.get_json()

    if not data or 'firstname' not in data or 'lastname' not in data or 'login' not in data or 'password' not in data or 'role' not in data:
        return jsonify({'message': 'Firstname, lastname, login, password, and role are required'}), 400

    firstname = data['firstname']
    lastname = data['lastname']
    login = data['login']
    password = data['password']
    role = data['role']

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('''SELECT userid FROM "User" WHERE login = %s''', (login,))
                if cur.fetchone():
                    return jsonify({'message': 'User already exists'}), 400

                cur.execute('''INSERT INTO "User" (firstname, lastname, login, password, role) VALUES (%s, %s, %s, %s, %s)''', 
                            (firstname, lastname, login, hashed_password, role))
                conn.commit()

        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    """Route pour la connexion et génération du token."""
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({'message': "Please provide a login and password"}), 400

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('''SELECT password, role FROM "User" WHERE login = %s''', (login,))
                user = cur.fetchone()

                if user and check_password_hash(user[0], password):
                    role = user[1]
                    access_token = create_access_token(identity=login, additional_claims={"role": role})
                    return jsonify(access_token=access_token), 200
                else:
                    return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/group', methods=['POST'])
@jwt_required()
def group():
    """Route pour la création d'un groupe."""
    claims = get_jwt_identity()
    role = claims.get('role', 'No role provided')

    if role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'message': 'Name is required'}), 400

    name = data['name']

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('''INSERT INTO "Group" (name) VALUES (%s) RETURNING groupid''', (name,))
                groupid = cur.fetchone()[0]
                conn.commit()

        return jsonify({'message': 'Group created successfully', 'groupid': groupid}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/remplir_group', methods=['POST'])
@jwt_required()
def remplir_group():
    """Route pour ajouter des utilisateurs à un groupe."""
    claims = get_jwt_identity()
    role = claims.get('role', 'No role provided')

    # Vérifiez si l'utilisateur est un administrateur
    if role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403

    # Obtenez les données de la requête
    data = request.get_json()
    if not data or 'group_id' not in data or 'user_ids' not in data:
        return jsonify({'message': 'Group ID and User IDs are required'}), 400

    groupid = data['groupid']
    userid = data['userid']

    if not isinstance(userid, list):
        return jsonify({'message': 'User IDs should be a list'}), 400

    cur = None

    try:
        # Connexion à la base de données
        conn = get_db_connection()
        cur = conn.cursor()

        # Assurez-vous que le groupe existe
        cur.execute('SELECT 1 FROM "Group" WHERE groupid = %s', (group_id,))
        if not cur.fetchone():
            return jsonify({'message': 'Group not found'}), 404

        # Ajoutez les utilisateurs au groupe
        for userid in userid:
            # Vérifiez si l'utilisateur existe
            cur.execute('SELECT 1 FROM "User" WHERE userid = %s', (userid,))
            if not cur.fetchone():
                return jsonify({'message': f'User with ID {userid} not found'}), 404
            
            # Ajoutez l'utilisateur au groupe
            cur.execute('INSERT INTO "Group_User" (groupid, userid) VALUES (%s, %s)', (groupid, userid))

        # Validez les changements
        conn.commit()

        return jsonify({'message': 'Users added to group successfully'}), 200

    except psycopg2.DatabaseError as db_err:
        if conn:
            conn.rollback()  # Annule les changements en cas d'erreur
        return jsonify({'message': 'Database error', 'error': str(db_err)}), 500

    except Exception as e:
        if conn:
            conn.rollback()  # Annule les changements en cas d'erreur
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500



    finally:
        cur.close()
        conn.close()



if __name__ == '__main__':
    app.run(debug=True)
