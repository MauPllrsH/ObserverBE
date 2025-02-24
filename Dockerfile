FROM python:3.9-slim

WORKDIR /app

RUN mkdir -p /app/data/geoip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY data/geoip/GeoLite2-City.mmdb /app/data/geoip/

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]