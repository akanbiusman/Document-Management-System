FROM python:3.9-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

ENV FLASK_APP=main.py

ENV FLASK_ENV=production

RUN mkdir -p /app/uploads

RUN python create_users.py

CMD ["flask", "run", "--host=0.0.0.0"]