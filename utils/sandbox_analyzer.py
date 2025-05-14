import os
import logging
import requests
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import hashlib
import time

class SandboxAnalyzer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config['sandbox']
        self.allowed_types = config['workflow']['sandbox_analysis']['allowed_file_types']
        self.timeout = config['workflow']['sandbox_analysis']['timeout_minutes']
        self.logger = logging.getLogger(__name__)

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _is_file_type_allowed(self, file_path: str) -> bool:
        """Check if file type is allowed for analysis"""
        _, ext = os.path.splitext(file_path)
        return ext.lower() in self.allowed_types

    def submit_for_analysis(self, file_path: str) -> Dict[str, Any]:
        """
        Submit a file for sandbox analysis
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if not self._is_file_type_allowed(file_path):
            return {
                "status": "skipped",
                "reason": "File type not allowed for sandbox analysis"
            }

        try:
            file_hash = self._calculate_file_hash(file_path)
            
            # Submit file to sandbox
            with open(file_path, 'rb') as file:
                headers = {'Authorization': f'Bearer {self.config["api_key"]}'}
                response = requests.post(
                    f"{self.config['api_url']}/submit",
                    headers=headers,
                    files={'file': file}
                )
                response.raise_for_status()
                task_id = response.json()['task_id']

            # Wait for analysis to complete
            result = self._poll_analysis_result(task_id)
            
            return {
                "status": "completed",
                "file_hash": file_hash,
                "analysis_results": result
            }

        except Exception as e:
            self.logger.error(f"Sandbox analysis failed: {str(e)}")
            return {
                "status": "failed",
                "error": str(e)
            }

    def _poll_analysis_result(self, task_id: str) -> Dict[str, Any]:
        """
        Poll for analysis results with timeout
        """
        start_time = datetime.now()
        timeout = timedelta(minutes=self.timeout)

        while datetime.now() - start_time < timeout:
            try:
                headers = {'Authorization': f'Bearer {self.config["api_key"]}'}
                response = requests.get(
                    f"{self.config['api_url']}/results/{task_id}",
                    headers=headers
                )
                response.raise_for_status()
                result = response.json()

                if result['status'] == 'completed':
                    return result

                time.sleep(30)  # Wait 30 seconds before next poll

            except Exception as e:
                self.logger.error(f"Error polling results: {str(e)}")
                raise

        raise TimeoutError("Sandbox analysis timed out")
