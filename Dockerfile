# Dockerfile pour l'application Flask CyberMetrics
# Utilise Python 3.11 slim pour une image legere

# Image de base Python 3.11 version allegee
FROM python:3.11-slim

# Definition du repertoire de travail dans le conteneur
WORKDIR /app

# Installation des dependances systeme necessaires pour psycopg2
# libpq-dev: bibliotheque client PostgreSQL
# gcc: compilateur C necessaire pour compiler psycopg2
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copie du fichier requirements.txt pour installer les dependances Python
COPY requirements.txt .

# Installation des dependances Python
# --no-cache-dir: n'utilise pas le cache pip pour reduire la taille de l'image
RUN pip install --no-cache-dir -r requirements.txt

# Copie de tout le code source de l'application
COPY . .

# Exposition du port 5000 (port par defaut de Flask)
EXPOSE 5000

# Variable d'environnement pour Flask
ENV FLASK_APP=app.py
ENV FLASK_ENV=development

# Commande de demarrage de l'application
# host=0.0.0.0: ecoute sur toutes les interfaces reseau
# port=5000: port d'ecoute
CMD ["python", "app.py"]
