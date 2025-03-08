#!/bin/bash
# Run environment scanner
./environment_scanner.py

# Generate attestation
SNAPSHOT=$(ls -t snapshots/*.json | head -1)
ATTESTATION=$(./attestation_generator.py $SNAPSHOT)

# Send alert if attestation is invalid
./alert.py $ATTESTATION admin@example.com security@example.com