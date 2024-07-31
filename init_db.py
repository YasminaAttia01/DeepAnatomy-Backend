from app import app, db

with app.app_context():
    db.create_all()
    print("Base de données initialisée avec succès.")
    print("Tables dans la base de données :")
    print(db.engine.table_names())
