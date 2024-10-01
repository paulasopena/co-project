FROM python:3.12-alpine 

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev

RUN pip install --upgrade pip

RUN pip install cryptography

EXPOSE 5005

COPY ./ ./src

WORKDIR ./src

CMD ["python3","onionRouter.py"]
