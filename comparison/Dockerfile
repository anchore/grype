FROM python:3

WORKDIR /
COPY vulnscan-reports /vulnscan-reports
COPY inline-reports /inline-reports
COPY compare.py .
ENTRYPOINT ["/compare.py"]