FROM python:3.9-slim
WORKDIR /app
COPY app.py .
RUN pip install Flask requests gunicorn
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
