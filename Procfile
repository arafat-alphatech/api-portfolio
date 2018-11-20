web: gunicorn -w 4 app:app
release: python3 api.py db migrate && python3 api.py db upgrade