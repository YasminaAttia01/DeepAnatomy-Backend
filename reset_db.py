import os
from app import db, app

# Supprimer le fichier de base de données existant
if os.path.exists('database.db'):
    os.remove('database.db')

# Recréer la base de données avec les nouvelles colonnes
with app.app_context():
    db.create_all()

print("Database has been reset.")
