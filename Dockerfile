FROM python:3.8.13-alpine3.15

RUN apk add build-base
RUN apk add libffi-dev
WORKDIR /usr/src/app

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV dbname=postgres
ENV dbuser=postgres
ENV dbpass=postgres
ENV dbpath=public
ENV dbhost=pg
ENV dbport=5432
ENV SENDGRID_API_KEY=sg_api_key

EXPOSE 8000

CMD python manage.py migrate; python manage.py runserver 0.0.0.0:8000