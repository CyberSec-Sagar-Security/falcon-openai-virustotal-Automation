import asyncio
import logging
from typing import List, Dict, Any, Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

class Orchestrator:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.max_concurrent_tasks = config['workflow']['max_concurrent_tasks']
        self.retry_attempts = config['workflow']['retry_attempts']
        self.retry_delay = config['workflow']['retry_delay_seconds']
        self.executor = ThreadPoolExecutor(max_workers=self.max_concurrent_tasks)
        self.logger = logging.getLogger(__name__)

    async def run_parallel_tasks(self, tasks: List[Callable], data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute multiple enrichment tasks in parallel
        """
        async def execute_task(task: Callable) -> Dict[str, Any]:
            for attempt in range(self.retry_attempts):
                try:
                    result = await asyncio.get_event_loop().run_in_executor(
                        self.executor, task, data
                    )
                    return result
                except Exception as e:
                    self.logger.error(f"Task failed (attempt {attempt + 1}/{self.retry_attempts}): {str(e)}")
                    if attempt < self.retry_attempts - 1:
                        await asyncio.sleep(self.retry_delay)
                    else:
                        return {"error": str(e), "task": task.__name__}

        tasks_coroutines = [execute_task(task) for task in tasks]
        return await asyncio.gather(*tasks_coroutines)

    async def process_alert(self, alert_data: Dict[str, Any], enrichment_tasks: List[Callable]) -> Dict[str, Any]:
        """
        Process a single alert through the entire workflow
        """
        alert_result = {
            "alert_data": alert_data,
            "processing_start": datetime.utcnow().isoformat(),
            "enrichments": [],
            "status": "processing"
        }

        try:
            # Run enrichment tasks in parallel
            enrichment_results = await self.run_parallel_tasks(enrichment_tasks, alert_data)
            alert_result["enrichments"] = enrichment_results
            alert_result["status"] = "completed"
        except Exception as e:
            self.logger.error(f"Alert processing failed: {str(e)}")
            alert_result["status"] = "failed"
            alert_result["error"] = str(e)

        alert_result["processing_end"] = datetime.utcnow().isoformat()
        return alert_result

    def shutdown(self):
        """
        Clean up resources
        """
        self.executor.shutdown(wait=True)
