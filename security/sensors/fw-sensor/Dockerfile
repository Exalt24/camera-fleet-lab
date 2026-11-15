FROM python:3.13-alpine
RUN apk add --no-cache tcpdump iptables
COPY fw_sensor.py /fw_sensor.py
ENTRYPOINT ["python", "-u", "/fw_sensor.py"]
