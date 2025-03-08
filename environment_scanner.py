#!/usr/bin/env python3
"""
Environment Scanner - Collects environment details for attestation generation

This module scans the build environment and collects information needed
to generate a secure attestation of the environment state.
"""

import os
import sys
import platform
import json
import subprocess
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("environment-scanner")

class EnvironmentScanner:
    """Scans the build environment and collects information for attestation."""

    def __init__(self, config_path: str = "config/scanner_config.json"):
        """
        Initialize the environment scanner.
        
        Args:
            config_path: Path to the scanner configuration file
        """
        self.config = self._load_config(config_path)
        self.build_id = os.environ.get("BUILD_ID", f"build-{int(datetime.now().timestamp())}")
        self.repo_info = self._get_repository_info()

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load scanner configuration from file.
        
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
                "required_env_vars": ["NODE_ENV", "BUILD_ID", "GIT_COMMIT"],
                "allowed_packages": {},
                "environment_name": "production",
                "hash_algorithm": "sha256"
            }

    def _get_repository_info(self) -> Dict[str, str]:
        """
        Get information about the Git repository.
        
        Returns:
            Dictionary containing repository information
        """
        repo_info = {
            "repository": "unknown",
            "branch": "unknown",
            "commit": "unknown"
        }
        
        try:
            # Get repository URL
            repo = subprocess.check_output(
                ["git", "config", "--get", "remote.origin.url"],
                universal_newlines=True
            ).strip()
            repo_info["repository"] = repo
            
            # Get branch name
            branch = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                universal_newlines=True
            ).strip()
            repo_info["branch"] = branch
            
            # Get commit hash
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                universal_newlines=True
            ).strip()
            repo_info["commit"] = commit
            
            logger.info(f"Repository info: {repo_info}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.warning(f"Failed to get repository info: {e}")
        
        return repo_info

    def get_os_info(self) -> Dict[str, str]:
        """
        Get operating system and kernel information.
        
        Returns:
            Dictionary containing OS and kernel details
        """
        os_info = {
            "os": f"{platform.system()} {platform.release()}",
            "kernel": platform.version(),
            "architecture": platform.machine(),
            "hostname": platform.node()
        }
        
        # Get more detailed OS info for Linux
        if platform.system() == "Linux":
            try:
                with open("/etc/os-release", "r") as f:
                    os_release = {}
                    for line in f:
                        key, value = line.rstrip().split("=", 1)
                        os_release[key] = value.strip('"')
                
                if "PRETTY_NAME" in os_release:
                    os_info["os"] = os_release["PRETTY_NAME"]
            except (FileNotFoundError, IOError) as e:
                logger.warning(f"Failed to get detailed OS info: {e}")
        
        logger.info(f"OS info: {os_info}")
        return os_info

    def get_python_packages(self) -> Dict[str, str]:
        """
        Get installed Python packages and their versions.
        
        Returns:
            Dictionary mapping package names to versions
        """
        packages = {}
        
        try:
            output = subprocess.check_output(
                [sys.executable, "-m", "pip", "freeze"],
                universal_newlines=True
            )
            
            for line in output.splitlines():
                if "==" in line:
                    name, version = line.split("==", 1)
                    packages[name] = version
            
            logger.info(f"Found {len(packages)} Python packages")
        except subprocess.SubprocessError as e:
            logger.warning(f"Failed to get Python packages: {e}")
        
        return packages

    def get_node_packages(self) -> Dict[str, str]:
        """
        Get installed Node.js packages and their versions.
        
        Returns:
            Dictionary mapping package names to versions
        """
        packages = {}
        
        try:
            # Check if npm is installed
            output = subprocess.check_output(
                ["npm", "--version"],
                universal_newlines=True
            )
            
            # Get node version
            node_version = subprocess.check_output(
                ["node", "--version"],
                universal_newlines=True
            ).strip()
            packages["nodejs"] = node_version.lstrip('v')
            
            # Get npm version
            npm_version = subprocess.check_output(
                ["npm", "--version"],
                universal_newlines=True
            ).strip()
            packages["npm"] = npm_version
            
            # Get installed packages (only production dependencies)
            # This checks the current directory for package.json
            try:
                output = subprocess.check_output(
                    ["npm", "list", "--prod", "--json"],
                    universal_newlines=True
                )
                npm_packages = json.loads(output)
                
                if "dependencies" in npm_packages:
                    for name, info in npm_packages["dependencies"].items():
                        packages[name] = info.get("version", "unknown")
                
                logger.info(f"Found {len(packages) - 2} Node.js packages")
            except (subprocess.SubprocessError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to get Node.js packages: {e}")
                
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.info("Node.js/npm not installed or not in PATH")
        
        return packages
    
    def get_docker_info(self) -> Dict[str, str]:
        """
        Get Docker version and information.
        
        Returns:
            Dictionary containing Docker information
        """
        docker_info = {}
        
        try:
            # Check if Docker is installed
            version_output = subprocess.check_output(
                ["docker", "--version"],
                universal_newlines=True
            ).strip()
            
            docker_info["docker"] = version_output.split(" ")[2].rstrip(",")
            
            # Get Docker Compose version if available
            try:
                compose_output = subprocess.check_output(
                    ["docker-compose", "--version"],
                    universal_newlines=True
                ).strip()
                docker_info["docker-compose"] = compose_output.split(" ")[2]
            except (subprocess.SubprocessError, FileNotFoundError, IndexError):
                logger.info("Docker Compose not installed or not in PATH")
            
            logger.info(f"Docker info: {docker_info}")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.info("Docker not installed or not in PATH")
        
        return docker_info

    def check_environment_variables(self) -> Dict[str, bool]:
        """
        Check if required environment variables are set.
        
        Returns:
            Dictionary mapping variable names to boolean indicating presence
        """
        required_vars = self.config.get("required_env_vars", [])
        results = {}
        
        for var in required_vars:
            results[var] = var in os.environ
            
        missing = [var for var, present in results.items() if not present]
        if missing:
            logger.warning(f"Missing required environment variables: {', '.join(missing)}")
        else:
            logger.info("All required environment variables are present")
        
        return results

    def hash_file(self, file_path: str) -> Optional[str]:
        """
        Generate hash for a file using the configured algorithm.
        
        Args:
            file_path: Path to the file to hash
            
        Returns:
            Hexadecimal hash digest or None if file cannot be read
        """
        algorithm = self.config.get("hash_algorithm", "sha256")
        hash_func = getattr(hashlib, algorithm)()
        
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            
            digest = hash_func.hexdigest()
            logger.info(f"Generated {algorithm} hash for {file_path}")
            return digest
        except (IOError, FileNotFoundError) as e:
            logger.warning(f"Failed to hash file {file_path}: {e}")
            return None

    def collect_all_data(self) -> Dict[str, Any]:
        """
        Collect all environment data for attestation.
        
        Returns:
            Dictionary containing all environment data
        """
        logger.info(f"Starting environment scan for build {self.build_id}")
        
        # Collect all environment data
        environment_data = {
            "buildId": self.build_id,
            "timestamp": datetime.utcnow().isoformat(),
            "environment": self.config.get("environment_name", "production"),
            "repository": self.repo_info.get("repository", "unknown"),
            "branch": self.repo_info.get("branch", "unknown"),
            "commit": self.repo_info.get("commit", "unknown"),
            "environmentData": {
                **self.get_os_info(),
                "packages": {
                    **self.get_python_packages(),
                    **self.get_node_packages(),
                    **self.get_docker_info()
                },
                "environmentVariables": self.check_environment_variables()
            }
        }
        
        logger.info("Environment scan completed")
        return environment_data

    def generate_snapshot(self, output_path: str = None) -> str:
        """
        Generate a snapshot of the environment and save to file.
        
        Args:
            output_path: Path to save the snapshot (or use default if None)
            
        Returns:
            Path to the saved snapshot file
        """
        environment_data = self.collect_all_data()
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"snapshots/{self.build_id}_{timestamp}.json"
            
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, "w") as f:
            json.dump(environment_data, f, indent=2)
            
        logger.info(f"Environment snapshot saved to {output_path}")
        return output_path


if __name__ == "__main__":
    # Example usage as a standalone script
    scanner = EnvironmentScanner()
    snapshot_path = scanner.generate_snapshot()
    print(f"Environment snapshot generated: {snapshot_path}")

