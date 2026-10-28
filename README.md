# CyberMetrics - Plateforme d'analyse de securite

Application web Flask demonstrant l'interaction avec une base de donnees PostgreSQL, incluant des requetes SQL complexes avec jointures.

## Technologies utilisees

- **Python 3.11** - Langage de programmation
- **Flask** - Framework web leger
- **PostgreSQL 15** - Base de donnees relationnelle
- **Docker & Docker Compose** - Conteneurisation
- **Chart.js** - Visualisations graphiques

## Structure du projet

```
bdd_app/
├── app.py                      # Application Flask principale
├── requirements.txt            # Dependances Python
├── Dockerfile                  # Image Docker pour l'app
├── docker-compose.example.yaml # Orchestration des services
├── init.sql                    # Script d'initialisation BDD
├── static/
│   └── css/
│       └── style.css          # Styles CSS (theme cyber dark)
└── templates/
    ├── base.html              # Template de base
    ├── index.html             # Dashboard
    ├── add.html               # Page d'ajout de donnees
    ├── tables.html            # Visualisation des tables
    └── analytics.html         # Graphiques et filtres
```

## Lancement de l'application

### Avec Docker Compose (recommande)

```bash
# Copier le fichier de configuration
cp docker-compose.example.yaml docker-compose.yaml

# Lancer les conteneurs
docker-compose up --build

# L'application est accessible sur http://localhost:5000
```

### Sans Docker (developpement local)

```bash
# Installer les dependances
pip install -r requirements.txt

# Configurer la variable d'environnement
export DATABASE_URL="postgresql://user:password@localhost:5432/cybermetrics"

# Lancer PostgreSQL et executer init.sql

# Lancer l'application
python app.py
```

## Schema de la base de donnees

### Tables

1. **servers** - Informations sur les serveurs surveilles
2. **threat_types** - Catalogue des types de menaces
3. **security_events** - Journal des evenements de securite
4. **network_metrics** - Metriques reseau collectees

### Relations (Foreign Keys)

- `security_events.server_id` → `servers.id`
- `security_events.threat_type_id` → `threat_types.id`
- `network_metrics.server_id` → `servers.id`

## Pages implementees

1. **Dashboard** (`/`) - Vue d'ensemble avec statistiques
2. **Ajouter** (`/add`) - Formulaires d'ajout de donnees
3. **Tables** (`/tables`) - Contenu brut des tables
4. **Analytics** (`/analytics`) - Graphiques avec filtres

## Requetes SQL avec jointures

L'application utilise plusieurs types de jointures:

### INNER JOIN
```sql
SELECT se.*, tt.name AS threat_name
FROM security_events se
JOIN threat_types tt ON se.threat_type_id = tt.id
```

### LEFT JOIN avec agregation
```sql
SELECT s.name, AVG(nm.bandwidth_in)
FROM servers s
LEFT JOIN network_metrics nm ON s.id = nm.server_id
GROUP BY s.id
```

### Double jointure
```sql
SELECT se.*, s.name AS server_name, tt.name AS threat_name
FROM security_events se
LEFT JOIN servers s ON se.server_id = s.id
LEFT JOIN threat_types tt ON se.threat_type_id = tt.id
```
