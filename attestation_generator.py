#!/usr/bin/env python3
"""
Attestation Generator - Creates secure attestations from environment data

This module processes environment data, verifies its integrity against
security policies, and generates cryptographically signed attestations.
"""

import os
import sys
import json
import logging
import hashlib
import hmac
import base64
from typing import Dict, List, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("attestation-generator")

class AttestationGenerator:
    """Generates secure attestations for build environments."""

    def __init__(self, config_path: str = "config/attestation_config.json"):
        """
        Initialize the attestation generator.
        
        Args:
            config_path: Path to the attestation configuration file
        """
        self.config = self._load_config(config_path)
        self.verification_results = []
        
        # Get signing key from environment variable or config
        # In production, this should come from a secure key management system
        self.signing_key = os.environ.get(
            "ATTESTATION_SIGNING_KEY", 
            self.config.get("signing_key", "development-key-only-for-testing")
        )

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load attestation configuration from file.
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Dictionary containing configuration
        """
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            logger.info(f"Loaded configuration from {config_path}")
            return config
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to load configuration: {e}")
            # Return default configuration
            return {
                "allowed_packages": {},
                "allowed_os": [
                    "Ubuntu 22.04",
                    "Ubuntu 20.04",
                    "Amazon Linux 2"
                ],
                "verification_rules": {
                    "check_os": True,
                    "check_packages": True,
                    "check_env_vars": True
                },
                "allowlist_policy": "strict",  # Options: strict, warn, log, disabled
                "storage_path": "attestations"
            }

    def verify_os(self, os_info: Dict[str, str]) -> Dict[str, Any]:
        """
        Verify OS against allowed list.
        
        Args:
            os_info: Dictionary containing OS information
            
        Returns:
            Verification result dictionary
        """
        os_name = os_info.get("os", "")
        allowed_os = self.config.get("allowed_os", [])
        
        # Check if any allowed OS is a substring of the actual OS
        is_allowed = any(allowed in os_name for allowed in allowed_os)
        
        result = {
            "check": "Environment Integrity",
            "description": "Verifies OS and kernel versions match expected values",
            "pass": is_allowed
        }
        
        if not is_allowed:
            result["errorDetails"] = f"OS '{os_name}' is not in the allowed list: {', '.join(allowed_os)}"
            logger.warning(result["errorDetails"])
        else:
            logger.info(f"OS verification passed: {os_name}")
            
        return result

    def verify_packages(self, packages: Dict[str, str]) -> Dict[str, Any]:
        """
        Verify installed packages against allowed versions.
        
        Args:
            packages: Dictionary mapping package names to versions
            
        Returns:
            Verification result dictionary
        """
        allowed_packages = self.config.get("allowed_packages", {})
        policy = self.config.get("allowlist_policy", "strict")
        
        # Check for unauthorized packages
        unauthorized = []
        for pkg, version in packages.items():
            if pkg not in allowed_packages:
                unauthorized.append(f"{pkg}@{version}")
                
        # Check for version mismatches
        version_mismatches = []
        for pkg, allowed_version in allowed_packages.items():
            if pkg in packages:
                actual_version = packages[pkg]
                if allowed_version != "*" and not self._version_matches(actual_version, allowed_version):
                    version_mismatches.append(f"{pkg}: expected {allowed_version}, got {actual_version}")
        
        if policy == "disabled":
            # Skip all package verification
            result = {
                "check": "Package Verification",
                "description": "Package verification is disabled",
                "pass": True
            }
        else:
            # Determine overall result based on policy
            if policy == "strict":
                passed = not unauthorized and not version_mismatches
            elif policy in ["warn", "log"]:
                passed = True  # Just log issues but don't fail
            else:
                passed = False  # Unknown policy
                
            result = {
                "check": "Package Verification",
                "description": "Checks installed packages against allowed versions",
                "pass": passed
            }
            
            # Add error details if there are issues
            errors = []
            if unauthorized:
                errors.append(f"Detected unauthorized packages: {', '.join(unauthorized)}")
            if version_mismatches:
                errors.append(f"Version mismatches: {', '.join(version_mismatches)}")
                
            if errors:
                result["errorDetails"] = ". ".join(errors)
                log_func = logger.warning if policy == "warn" else logger.info
                log_func(result["errorDetails"])
            else:
                logger.info("Package verification passed")
                
        return result

    def _version_matches(self, actual: str, required: str) -> bool:
        """
        Check if package version matches required version.
        
        Supports basic semver with wildcards and ^ prefix.
        
        Args:
            actual: Actual version string
            required: Required version string with possible special chars
            
        Returns:
            True if versions match according to requirement
        """
        # Exact match
        if required == actual:
            return True
            
        # Wildcard
        if required == "*":
            return True
            
        # Caret requirement (^): Compatible with version, allowing minor/patch updates
        if required.startswith("^"):
            req_version = required[1:].split(".")
            act_version = actual.split(".")
            
            # Check major version matches
            if len(req_version) > 0 and len(act_version) > 0:
                return req_version[0] == act_version[0]
                
        # Tilde requirement (~): Compatible with version, allowing only patch updates
        if required.startswith("~"):
            req_version = required[1:].split(".")
            act_version = actual.split(".")
            
            # Check major and minor versions match
            if len(req_version) >= 2 and len(act_version) >= 2:
                return req_version[0] == act_version[0] and req_version[1] == act_version[1]
                
        return False

    def verify_env_vars(self, env_vars: Dict[str, bool]) -> Dict[str, Any]:
        """
        Verify required environment variables are present.
        
        Args:
            env_vars: Dictionary mapping variable names to presence boolean
            
        Returns:
            Verification result dictionary
        """
        missing = [var for var, present in env_vars.items() if not present]
        
        result = {
            "check": "Environment Variables",
            "description": "Verifies required environment variables are present",
            "pass": not missing
        }
        
        if missing:
            result["errorDetails"] = f"Missing required environment variables: {', '.join(missing)}"
            logger.warning(result["errorDetails"])
        else:
            logger.info("Environment variables verification passed")
            
        return result

    def verify_snapshot(self, snapshot_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Verify all aspects of an environment snapshot.
        
        Args:
            snapshot_data: Dictionary containing environment snapshot data
            
        Returns:
            List of verification result dictionaries
        """
        verification_rules = self.config.get("verification_rules", {})
        results = []
        
        # Extract data from snapshot
        env_data = snapshot_data.get("environmentData", {})
        os_info = {k: v for k, v in env_data.items() if k != "packages" and k != "environmentVariables"}
        packages = env_data.get("packages", {})
        env_vars = env_data.get("environmentVariables", {})
        
        # Run verification checks based on configuration
        if verification_rules.get("check_os", True):
            results.append(self.verify_os(os_info))
            
        if verification_rules.get("check_packages", True):
            results.append(self.verify_packages(packages))
            
        if verification_rules.get("check_env_vars", True):
            results.append(self.verify_env_vars(env_vars))
            
        self.verification_results = results
        return results

    def calculate_signature(self, data: Dict[str, Any]) -> str:
        """
        Calculate HMAC signature for attestation data.
        
        Args:
            data: Dictionary containing attestation data
            
        Returns:
            Base64-encoded HMAC signature
        """
        # Convert data to canonical JSON string
        canonical_data = json.dumps(data, separators=(',', ':'), sort_keys=True)
        
        # Calculate HMAC using SHA-256
        signature = hmac.new(
            self.signing_key.encode('utf-8'),
            canonical_data.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        # Return base64 encoded signature
        return base64.b64encode(signature).decode('utf-8')

    def generate_attestation(self, snapshot_path: str) -> Dict[str, Any]:
        """
        Generate attestation from environment snapshot.
        
        Args:
            snapshot_path: Path to the environment snapshot file
            
        Returns:
            Dictionary containing the attestation
        """
        # Load snapshot data
        with open(snapshot_path, 'r') as f:
            snapshot_data = json.load(f)
            
        logger.info(f"Generating attestation for snapshot: {snapshot_path}")
        
        # Verify snapshot data
        verification_results = self.verify_snapshot(snapshot_data)
        
        # Determine overall verification status
        valid = all(result["pass"] for result in verification_results)
        
        # Build attestation
        attestation = {
            "buildId": snapshot_data.get("buildId", f"build-{int(datetime.now().timestamp())}"),
            "timestamp": snapshot_data.get("timestamp", datetime.utcnow().isoformat()),
            "environment": snapshot_data.get("environment", "production"),
            "repository": snapshot_data.get("repository", "unknown"),
            "branch": snapshot_data.get("branch", "unknown"),
            "commit": snapshot_data.get("commit", "unknown"),
            "valid": valid,
            "environmentData": snapshot_data.get("environmentData", {}),
            "verificationResults": verification_results
        }
        
        # Calculate signature
        attestation["signature"] = self.calculate_signature(attestation)
        
        logger.info(f"Generated attestation for build {attestation['buildId']} (valid: {valid})")
        return attestation

    def save_attestation(self, attestation: Dict[str, Any], output_path: str = None) -> str:
        """
        Save attestation to file.
        
        Args:
            attestation: Dictionary containing the attestation
            output_path: Path to save the attestation (or use default if None)
            
        Returns:
            Path to the saved attestation file
        """
        if output_path is None:
            storage_path = self.config.get("storage_path", "attestations")
            build_id = attestation.get("buildId", f"build-{int(datetime.now().timestamp())}")
            output_path = f"{storage_path}/{build_id}.json"
            
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, "w") as f:
            json.dump(attestation, f, indent=2)
            
        logger.info(f"Attestation saved to {output_path}")
        return output_path


if __name__ == "__main__":
    # Example usage as a standalone script
    if len(sys.argv) < 2:
        print("Usage: attestation_generator.py <snapshot_path>")
        sys.exit(1)
        
    snapshot_path = sys.argv[1]
    generator = AttestationGenerator()
    attestation = generator.generate_attestation(snapshot_path)
    output_path = generator.save_attestation(attestation)
    print(f"Attestation generated and saved to {output_path}")

