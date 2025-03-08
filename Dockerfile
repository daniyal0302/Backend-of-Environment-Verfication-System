FROM python:3.10-slim

WORKDIR /app

COPY environment_scanner.py attestation_generator.py ./
COPY config/ ./config/

RUN mkdir -p snapshots attestations
RUN chmod +x environment_scanner.py attestation_generator.py

ENV BUILD_ID=docker-build
ENV NODE_ENV=production
ENV GIT_COMMIT=unknown

CMD ["./environment_scanner.py"]