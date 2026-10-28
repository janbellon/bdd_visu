# Application Flask CyberMetrics
# Plateforme d'analyse de metriques de securite reseau
# Cette application demonstre l'utilisation de PostgreSQL avec des jointures SQL complexes

# Import des modules necessaires
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import psycopg2
from psycopg2.extras import RealDictCursor

# Creation de l'instance Flask
# __name__ permet a Flask de localiser les templates et fichiers statiques
app = Flask(__name__)

# Cle secrete pour les sessions Flask (messages flash)
# En production, utiliser une cle aleatoire stockee dans les variables d'environnement
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')


def get_db_connection():
    """
    Etablit une connexion a la base de donnees PostgreSQL.

    Utilise la variable d'environnement DATABASE_URL pour la configuration.
    RealDictCursor permet de recuperer les resultats sous forme de dictionnaires
    au lieu de tuples, ce qui facilite l'acces aux colonnes par leur nom.

    Returns:
        psycopg2.connection: Objet de connexion a la base de donnees
    """
    # Recuperation de l'URL de connexion depuis les variables d'environnement
    database_url = os.environ.get('DATABASE_URL', 'postgresql://cyber_user:cyber_password_secure_123@localhost:5432/cybermetrics')

    # Etablissement de la connexion avec curseur dictionnaire
    conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
    return conn


# ============================================================
# ROUTE: Page d'accueil (Dashboard)
# Affiche un resume des metriques de securite
# ============================================================
@app.route('/')
def index():
    """
    Page d'accueil - Dashboard avec statistiques globales.

    Utilise plusieurs requetes SQL avec jointures pour calculer:
    - Nombre total d'evenements de securite
    - Nombre d'evenements par statut
    - Derniers evenements avec details du serveur et type de menace
    """
    conn = get_db_connection()
    cur = conn.cursor()

    # Requete 1: Compte total des evenements de securite
    cur.execute('SELECT COUNT(*) as total FROM security_events')
    total_events = cur.fetchone()['total']

    # Requete 2: Nombre de serveurs actifs
    cur.execute("SELECT COUNT(*) as total FROM servers WHERE status = 'active'")
    active_servers = cur.fetchone()['total']

    # Requete 3: Evenements critiques (severite >= 4) avec JOINTURE
    # Cette requete joint security_events avec threat_types pour filtrer par severite
    cur.execute('''
        SELECT COUNT(*) as total
        FROM security_events se
        JOIN threat_types tt ON se.threat_type_id = tt.id
        WHERE tt.severity_level >= 4 AND se.status != 'resolved'
    ''')
    critical_events = cur.fetchone()['total']

    # Requete 4: Derniers evenements avec DOUBLE JOINTURE
    # Joint security_events avec servers ET threat_types pour afficher les details
    cur.execute('''
        SELECT
            se.id,
            se.source_ip,
            se.event_timestamp,
            se.status,
            s.name as server_name,
            s.ip_address as server_ip,
            tt.name as threat_name,
            tt.severity_level
        FROM security_events se
        LEFT JOIN servers s ON se.server_id = s.id
        LEFT JOIN threat_types tt ON se.threat_type_id = tt.id
        ORDER BY se.event_timestamp DESC
        LIMIT 5
    ''')
    recent_events = cur.fetchall()

    # Fermeture de la connexion
    cur.close()
    conn.close()

    # Rendu du template avec les donnees
    return render_template('index.html',
                         total_events=total_events,
                         active_servers=active_servers,
                         critical_events=critical_events,
                         recent_events=recent_events)


# ============================================================
# ROUTE: Page d'ajout de donnees
# Formulaires pour ajouter serveurs, menaces et evenements
# ============================================================
@app.route('/add', methods=['GET', 'POST'])
def add_data():
    """
    Page d'ajout de donnees.

    GET: Affiche les formulaires d'ajout
    POST: Traite les soumissions de formulaires

    Permet d'ajouter:
    - Nouveaux serveurs
    - Nouveaux types de menaces
    - Nouveaux evenements de securite
    """
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        # Determination du type de donnee a ajouter
        form_type = request.form.get('form_type')

        if form_type == 'server':
            # Ajout d'un nouveau serveur
            # Recuperation des valeurs du formulaire
            name = request.form['name']
            ip_address = request.form['ip_address']
            server_type = request.form['server_type']
            location = request.form['location']
            status = request.form['status']

            # Insertion dans la base de donnees
            # Utilisation de parametres pour eviter les injections SQL
            cur.execute('''
                INSERT INTO servers (name, ip_address, server_type, location, status)
                VALUES (%s, %s, %s, %s, %s)
            ''', (name, ip_address, server_type, location, status))
            conn.commit()
            flash('Serveur ajoute avec succes!', 'success')

        elif form_type == 'threat':
            # Ajout d'un nouveau type de menace
            name = request.form['name']
            severity_level = int(request.form['severity_level'])
            description = request.form['description']
            category = request.form['category']

            cur.execute('''
                INSERT INTO threat_types (name, severity_level, description, category)
                VALUES (%s, %s, %s, %s)
            ''', (name, severity_level, description, category))
            conn.commit()
            flash('Type de menace ajoute avec succes!', 'success')

        elif form_type == 'event':
            # Ajout d'un nouvel evenement de securite
            server_id = int(request.form['server_id'])
            threat_type_id = int(request.form['threat_type_id'])
            source_ip = request.form['source_ip']
            status = request.form['status']
            details = request.form['details']

            cur.execute('''
                INSERT INTO security_events (server_id, threat_type_id, source_ip, status, details)
                VALUES (%s, %s, %s, %s, %s)
            ''', (server_id, threat_type_id, source_ip, status, details))
            conn.commit()
            flash('Evenement de securite ajoute avec succes!', 'success')

    # Recuperation des listes pour les menus deroulants
    cur.execute('SELECT id, name FROM servers ORDER BY name')
    servers = cur.fetchall()

    cur.execute('SELECT id, name, severity_level FROM threat_types ORDER BY name')
    threat_types = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('add.html', servers=servers, threat_types=threat_types)


# ============================================================
# ROUTE: Visualisation des tables
# Affiche le contenu brut des tables de la base de donnees
# ============================================================
@app.route('/tables')
def view_tables():
    """
    Page de visualisation des tables.

    Affiche le contenu de toutes les tables de la base de donnees
    avec possibilite de filtrer par table specifique.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    # Recuperation du parametre de table (optionnel)
    selected_table = request.args.get('table', 'all')

    tables_data = {}

    # Liste des tables a afficher
    table_names = ['servers', 'threat_types', 'security_events', 'network_metrics']

    for table_name in table_names:
        if selected_table == 'all' or selected_table == table_name:
            # Requete pour recuperer toutes les donnees de la table
            # ATTENTION: En production, limiter le nombre de lignes
            cur.execute(f'SELECT * FROM {table_name} ORDER BY id DESC LIMIT 100')
            tables_data[table_name] = {
                'columns': [desc[0] for desc in cur.description],
                'rows': cur.fetchall()
            }

    cur.close()
    conn.close()

    return render_template('tables.html',
                         tables_data=tables_data,
                         selected_table=selected_table,
                         table_names=table_names)


# ============================================================
# ROUTE: Page de visualisation graphique
# Graphiques et statistiques avec filtres
# ============================================================
@app.route('/analytics')
def analytics():
    """
    Page d'analytique avec graphiques.

    Affiche des visualisations basees sur des requetes SQL complexes:
    - Evenements par type de menace (avec jointure)
    - Evolution temporelle des evenements
    - Metriques reseau par serveur (avec jointure)
    - Distribution par severite
    """
    conn = get_db_connection()
    cur = conn.cursor()

    # Recuperation des filtres depuis les parametres URL
    date_filter = request.args.get('days', '7')  # Par defaut: 7 derniers jours
    server_filter = request.args.get('server', 'all')

    # Conversion du filtre de date en intervalle
    try:
        days = int(date_filter)
    except ValueError:
        days = 7

    # Construction de la clause WHERE pour le filtre serveur
    server_clause = ""
    server_params = []
    if server_filter != 'all':
        server_clause = "AND se.server_id = %s"
        server_params = [int(server_filter)]

    # --------------------------------------------------------
    # REQUETE 1: Evenements par type de menace avec JOINTURE
    # Joint security_events avec threat_types pour grouper par nom de menace
    # --------------------------------------------------------
    query1 = f'''
        SELECT
            tt.name as threat_name,
            tt.severity_level,
            COUNT(se.id) as event_count
        FROM threat_types tt
        LEFT JOIN security_events se ON tt.id = se.threat_type_id
            AND se.event_timestamp >= NOW() - INTERVAL '{days} days'
            {server_clause}
        GROUP BY tt.id, tt.name, tt.severity_level
        ORDER BY event_count DESC
    '''
    cur.execute(query1, server_params)
    events_by_threat = cur.fetchall()

    # --------------------------------------------------------
    # REQUETE 2: Evolution temporelle des evenements par jour
    # Utilise DATE_TRUNC pour grouper par jour
    # --------------------------------------------------------
    query2 = f'''
        SELECT
            DATE_TRUNC('day', se.event_timestamp) as event_date,
            COUNT(*) as event_count
        FROM security_events se
        WHERE se.event_timestamp >= NOW() - INTERVAL '{days} days'
        {server_clause.replace('AND', 'AND') if server_clause else ''}
        GROUP BY DATE_TRUNC('day', se.event_timestamp)
        ORDER BY event_date ASC
    '''
    cur.execute(query2, server_params)
    events_timeline = cur.fetchall()

    # --------------------------------------------------------
    # REQUETE 3: Metriques reseau moyennes par serveur avec JOINTURE
    # Joint network_metrics avec servers pour afficher le nom du serveur
    # --------------------------------------------------------
    query3 = '''
        SELECT
            s.name as server_name,
            s.server_type,
            ROUND(AVG(nm.bandwidth_in)::numeric, 2) as avg_bandwidth_in,
            ROUND(AVG(nm.bandwidth_out)::numeric, 2) as avg_bandwidth_out,
            ROUND(AVG(nm.latency_ms)::numeric, 2) as avg_latency,
            ROUND(AVG(nm.active_connections)::numeric, 0) as avg_connections
        FROM servers s
        LEFT JOIN network_metrics nm ON s.id = nm.server_id
        GROUP BY s.id, s.name, s.server_type
        HAVING COUNT(nm.id) > 0
        ORDER BY avg_bandwidth_out DESC
    '''
    cur.execute(query3)
    network_by_server = cur.fetchall()

    # --------------------------------------------------------
    # REQUETE 4: Distribution par statut avec JOINTURE
    # Compte les evenements par statut et severite moyenne
    # --------------------------------------------------------
    query4 = f'''
        SELECT
            se.status,
            COUNT(*) as count,
            ROUND(AVG(tt.severity_level)::numeric, 1) as avg_severity
        FROM security_events se
        LEFT JOIN threat_types tt ON se.threat_type_id = tt.id
        WHERE se.event_timestamp >= NOW() - INTERVAL '{days} days'
        {server_clause}
        GROUP BY se.status
        ORDER BY count DESC
    '''
    cur.execute(query4, server_params)
    events_by_status = cur.fetchall()

    # --------------------------------------------------------
    # REQUETE 5: Top 5 sources d'attaques
    # Agregation des evenements par IP source
    # --------------------------------------------------------
    query5 = f'''
        SELECT
            se.source_ip,
            COUNT(*) as attack_count,
            ROUND(AVG(tt.severity_level)::numeric, 1) as avg_severity,
            ARRAY_AGG(DISTINCT tt.name) as threat_types
        FROM security_events se
        LEFT JOIN threat_types tt ON se.threat_type_id = tt.id
        WHERE se.event_timestamp >= NOW() - INTERVAL '{days} days'
        {server_clause}
        GROUP BY se.source_ip
        ORDER BY attack_count DESC
        LIMIT 5
    '''
    cur.execute(query5, server_params)
    top_attackers = cur.fetchall()

    # Recuperation de la liste des serveurs pour le filtre
    cur.execute('SELECT id, name FROM servers ORDER BY name')
    servers = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('analytics.html',
                         events_by_threat=events_by_threat,
                         events_timeline=events_timeline,
                         network_by_server=network_by_server,
                         events_by_status=events_by_status,
                         top_attackers=top_attackers,
                         servers=servers,
                         current_days=days,
                         current_server=server_filter)


# ============================================================
# ROUTE API: Donnees JSON pour les graphiques
# Endpoint pour les appels AJAX depuis le frontend
# ============================================================
@app.route('/api/metrics')
def api_metrics():
    """
    API endpoint retournant les metriques en JSON.

    Utilise pour les mises a jour dynamiques des graphiques
    sans rechargement de page.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    server_id = request.args.get('server_id', None)

    # Requete des dernieres metriques avec JOINTURE
    if server_id:
        cur.execute('''
            SELECT
                nm.timestamp,
                nm.bandwidth_in,
                nm.bandwidth_out,
                nm.latency_ms,
                nm.active_connections,
                s.name as server_name
            FROM network_metrics nm
            JOIN servers s ON nm.server_id = s.id
            WHERE nm.server_id = %s
            ORDER BY nm.timestamp DESC
            LIMIT 24
        ''', (server_id,))
    else:
        cur.execute('''
            SELECT
                nm.timestamp,
                nm.bandwidth_in,
                nm.bandwidth_out,
                nm.latency_ms,
                nm.active_connections,
                s.name as server_name
            FROM network_metrics nm
            JOIN servers s ON nm.server_id = s.id
            ORDER BY nm.timestamp DESC
            LIMIT 50
        ''')

    metrics = cur.fetchall()

    cur.close()
    conn.close()

    # Conversion des timestamps en format ISO pour JSON
    result = []
    for m in metrics:
        result.append({
            'timestamp': m['timestamp'].isoformat() if m['timestamp'] else None,
            'bandwidth_in': float(m['bandwidth_in']) if m['bandwidth_in'] else 0,
            'bandwidth_out': float(m['bandwidth_out']) if m['bandwidth_out'] else 0,
            'latency_ms': float(m['latency_ms']) if m['latency_ms'] else 0,
            'active_connections': int(m['active_connections']) if m['active_connections'] else 0,
            'server_name': m['server_name']
        })

    return jsonify(result)


# ============================================================
# Point d'entree de l'application
# ============================================================
if __name__ == '__main__':
    # Demarrage du serveur Flask
    # host='0.0.0.0': ecoute sur toutes les interfaces (necessaire pour Docker)
    # port=5000: port d'ecoute
    # debug=True: mode debug avec rechargement automatique
    app.run(host='0.0.0.0', port=5000, debug=True)
