from typing import Dict, Any, Optional
import importlib
import logging

logger = logging.getLogger(__name__)

class ModuleManager:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled_modules = config.get('enabled_modules', {})
        self.loaded_modules = {}

    def load_module(self, module_name: str) -> Optional[Any]:
        """Load a module if it's enabled in configuration."""
        if not self.is_module_enabled(module_name):
            logger.info(f"Module {module_name} is disabled in configuration")
            return None

        try:
            if module_name not in self.loaded_modules:
                module = importlib.import_module(f'utils.{module_name}')
                self.loaded_modules[module_name] = module
            return self.loaded_modules[module_name]
        except ImportError as e:
            logger.warning(f"Failed to load module {module_name}: {str(e)}")
            return None

    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a module is enabled in configuration."""
        return self.enabled_modules.get(module_name, False)

    def get_enabled_modules(self) -> Dict[str, bool]:
        """Get a dictionary of all modules and their enabled status."""
        return self.enabled_modules
