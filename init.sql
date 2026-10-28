-- Script d'initialisation de la base de donnees CyberMetrics
-- Ce script cree les tables et insere des donnees de demonstration
-- Il est execute automatiquement au premier demarrage de PostgreSQL

-- ============================================================
-- TABLE: servers
-- Description: Stocke les informations sur les serveurs surveilles
-- Chaque serveur a un nom, une IP, un type et une localisation
-- ============================================================
CREATE TABLE IF NOT EXISTS servers (
    -- Identifiant unique auto-incremente
    id SERIAL PRIMARY KEY,
    -- Nom du serveur (ex: "web-prod-01")
    name VARCHAR(100) NOT NULL,
    -- Adresse IP du serveur
    ip_address VARCHAR(45) NOT NULL,
    -- Type de serveur (web, database, api, cache, etc.)
    server_type VARCHAR(50) NOT NULL,
    -- Localisation geographique (datacenter)
    location VARCHAR(100),
    -- Statut actuel du serveur
    status VARCHAR(20) DEFAULT 'active',
    -- Date de creation de l'enregistrement
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- TABLE: threat_types
-- Description: Catalogue des types de menaces detectables
-- Permet de categoriser les alertes de securite
-- ============================================================
CREATE TABLE IF NOT EXISTS threat_types (
    -- Identifiant unique auto-incremente
    id SERIAL PRIMARY KEY,
    -- Nom de la menace (ex: "SQL Injection", "DDoS")
    name VARCHAR(100) NOT NULL,
    -- Niveau de severite de 1 (faible) a 5 (critique)
    severity_level INTEGER CHECK (severity_level BETWEEN 1 AND 5),
    -- Description detaillee de la menace
    description TEXT,
    -- Categorie de la menace (network, application, data, etc.)
    category VARCHAR(50)
);

-- ============================================================
-- TABLE: security_events
-- Description: Journal des evenements de securite detectes
-- Contient les alertes avec reference au serveur et type de menace
-- Cette table utilise des FOREIGN KEYS pour les jointures
-- ============================================================
CREATE TABLE IF NOT EXISTS security_events (
    -- Identifiant unique auto-incremente
    id SERIAL PRIMARY KEY,
    -- Reference vers le serveur concerne (FOREIGN KEY)
    server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
    -- Reference vers le type de menace (FOREIGN KEY)
    threat_type_id INTEGER REFERENCES threat_types(id) ON DELETE SET NULL,
    -- Adresse IP source de l'attaque
    source_ip VARCHAR(45),
    -- Date et heure de l'evenement
    event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Statut de l'evenement (detected, investigating, resolved, false_positive)
    status VARCHAR(30) DEFAULT 'detected',
    -- Details supplementaires en format texte
    details TEXT
);

-- ============================================================
-- TABLE: network_metrics
-- Description: Metriques reseau collectees periodiquement
-- Stocke bande passante, latence, paquets pour chaque serveur
-- ============================================================
CREATE TABLE IF NOT EXISTS network_metrics (
    -- Identifiant unique auto-incremente
    id SERIAL PRIMARY KEY,
    -- Reference vers le serveur concerne (FOREIGN KEY)
    server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
    -- Date et heure de la mesure
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Bande passante entrante en Mbps
    bandwidth_in DECIMAL(10, 2),
    -- Bande passante sortante en Mbps
    bandwidth_out DECIMAL(10, 2),
    -- Latence en millisecondes
    latency_ms DECIMAL(8, 2),
    -- Nombre de paquets perdus
    packet_loss INTEGER DEFAULT 0,
    -- Nombre de connexions actives
    active_connections INTEGER DEFAULT 0
);

-- ============================================================
-- INSERTION DE DONNEES DE DEMONSTRATION
-- Ces donnees permettent de tester l'application immediatement
-- ============================================================

-- Insertion des serveurs de demonstration
INSERT INTO servers (name, ip_address, server_type, location, status) VALUES
    ('web-prod-01', '192.168.1.10', 'web', 'Paris DC1', 'active'),
    ('web-prod-02', '192.168.1.11', 'web', 'Paris DC1', 'active'),
    ('api-prod-01', '192.168.1.20', 'api', 'Paris DC2', 'active'),
    ('db-master-01', '192.168.1.30', 'database', 'Paris DC1', 'active'),
    ('db-replica-01', '192.168.1.31', 'database', 'Lyon DC1', 'active'),
    ('cache-01', '192.168.1.40', 'cache', 'Paris DC1', 'active'),
    ('monitor-01', '192.168.1.50', 'monitoring', 'Paris DC2', 'active'),
    ('backup-01', '192.168.1.60', 'backup', 'Lyon DC1', 'maintenance');

-- Insertion des types de menaces
INSERT INTO threat_types (name, severity_level, description, category) VALUES
    ('SQL Injection', 5, 'Tentative injection de code SQL malveillant', 'application'),
    ('DDoS Attack', 5, 'Attaque par deni de service distribue', 'network'),
    ('Brute Force', 4, 'Tentative de connexion par force brute', 'authentication'),
    ('XSS Attack', 4, 'Tentative de cross-site scripting', 'application'),
    ('Port Scan', 2, 'Scan de ports detecte', 'network'),
    ('Malware Detected', 5, 'Logiciel malveillant detecte', 'malware'),
    ('Unauthorized Access', 4, 'Tentative acces non autorise', 'authentication'),
    ('Data Exfiltration', 5, 'Tentative exfiltration de donnees', 'data'),
    ('Suspicious Traffic', 3, 'Trafic reseau suspect detecte', 'network'),
    ('Configuration Change', 2, 'Modification configuration non planifiee', 'system');

-- Insertion des evenements de securite (avec dates variees pour les graphiques)
INSERT INTO security_events (server_id, threat_type_id, source_ip, event_timestamp, status, details) VALUES
    (1, 1, '45.33.32.156', NOW() - INTERVAL '1 day', 'resolved', 'Tentative SQLi sur /api/users bloquee'),
    (1, 4, '185.220.101.1', NOW() - INTERVAL '2 days', 'resolved', 'XSS detecte dans formulaire contact'),
    (2, 3, '91.121.87.45', NOW() - INTERVAL '3 hours', 'investigating', 'Multiple tentatives login admin'),
    (3, 2, '103.21.244.0', NOW() - INTERVAL '12 hours', 'detected', 'Pic de trafic anormal detecte'),
    (4, 1, '45.33.32.156', NOW() - INTERVAL '5 days', 'resolved', 'SQLi sur endpoint /api/data'),
    (1, 5, '192.168.100.55', NOW() - INTERVAL '1 hour', 'false_positive', 'Scan interne autorise'),
    (3, 9, '185.199.108.1', NOW() - INTERVAL '6 hours', 'investigating', 'Pattern de trafic inhabituel'),
    (2, 3, '91.121.87.45', NOW() - INTERVAL '2 days', 'resolved', 'Brute force bloque apres 50 tentatives'),
    (5, 7, '10.0.0.55', NOW() - INTERVAL '4 days', 'resolved', 'Tentative acces replica sans autorisation'),
    (4, 8, '45.76.113.87', NOW() - INTERVAL '8 hours', 'investigating', 'Transfert donnees suspect detecte'),
    (1, 2, '103.21.244.0', NOW() - INTERVAL '10 days', 'resolved', 'DDoS Layer 7 mitige'),
    (6, 10, '192.168.1.100', NOW() - INTERVAL '1 day', 'resolved', 'Config Redis modifiee'),
    (3, 4, '185.220.101.1', NOW() - INTERVAL '7 days', 'resolved', 'XSS reflected bloque par WAF'),
    (2, 1, '45.33.32.156', NOW() - INTERVAL '9 days', 'resolved', 'SQLi time-based detectee'),
    (7, 5, '10.0.0.1', NOW() - INTERVAL '30 minutes', 'false_positive', 'Scan Nessus planifie');

-- Insertion des metriques reseau (donnees sur plusieurs jours)
-- Generation de metriques pour simuler un historique realiste
INSERT INTO network_metrics (server_id, timestamp, bandwidth_in, bandwidth_out, latency_ms, packet_loss, active_connections) VALUES
    -- Metriques web-prod-01
    (1, NOW() - INTERVAL '6 hours', 450.25, 1200.50, 12.5, 0, 1520),
    (1, NOW() - INTERVAL '5 hours', 520.30, 1350.75, 11.2, 2, 1680),
    (1, NOW() - INTERVAL '4 hours', 680.45, 1580.20, 15.8, 5, 2100),
    (1, NOW() - INTERVAL '3 hours', 890.60, 2100.30, 22.3, 12, 2850),
    (1, NOW() - INTERVAL '2 hours', 750.20, 1800.45, 18.1, 3, 2200),
    (1, NOW() - INTERVAL '1 hour', 480.15, 1150.60, 10.5, 0, 1450),
    (1, NOW(), 510.40, 1280.90, 11.8, 1, 1600),
    -- Metriques web-prod-02
    (2, NOW() - INTERVAL '6 hours', 380.15, 980.30, 11.2, 0, 1200),
    (2, NOW() - INTERVAL '5 hours', 420.50, 1100.45, 10.8, 1, 1350),
    (2, NOW() - INTERVAL '4 hours', 550.80, 1320.60, 14.2, 3, 1680),
    (2, NOW() - INTERVAL '3 hours', 720.30, 1750.80, 19.5, 8, 2300),
    (2, NOW() - INTERVAL '2 hours', 610.45, 1480.20, 16.3, 2, 1850),
    (2, NOW() - INTERVAL '1 hour', 400.20, 950.70, 9.8, 0, 1180),
    (2, NOW(), 430.60, 1020.40, 10.2, 0, 1280),
    -- Metriques api-prod-01
    (3, NOW() - INTERVAL '6 hours', 280.40, 650.20, 8.5, 0, 3200),
    (3, NOW() - INTERVAL '5 hours', 350.60, 780.45, 9.2, 1, 3800),
    (3, NOW() - INTERVAL '4 hours', 520.80, 1150.30, 12.8, 4, 5200),
    (3, NOW() - INTERVAL '3 hours', 680.20, 1480.60, 18.5, 10, 6800),
    (3, NOW() - INTERVAL '2 hours', 450.30, 980.40, 11.2, 2, 4500),
    (3, NOW() - INTERVAL '1 hour', 300.15, 680.80, 8.8, 0, 3400),
    (3, NOW(), 320.50, 720.30, 9.0, 0, 3600),
    -- Metriques db-master-01
    (4, NOW() - INTERVAL '6 hours', 150.20, 320.40, 2.5, 0, 180),
    (4, NOW() - INTERVAL '5 hours', 180.45, 380.60, 2.8, 0, 210),
    (4, NOW() - INTERVAL '4 hours', 250.80, 520.30, 3.5, 1, 280),
    (4, NOW() - INTERVAL '3 hours', 320.60, 680.45, 4.2, 2, 350),
    (4, NOW() - INTERVAL '2 hours', 220.30, 450.20, 3.0, 0, 240),
    (4, NOW() - INTERVAL '1 hour', 160.15, 340.60, 2.6, 0, 190),
    (4, NOW(), 170.40, 360.80, 2.7, 0, 200);
