"""Package-to-import module name resolution."""

import importlib.metadata
import logging
from typing import Dict, List, Optional
from risk_agent.models.schemas import ImportResolution
from risk_agent.parser.diff_parser import canonicalize_name
from risk_agent.resolver.static_mappings import STATIC_PACKAGE_TO_MODULE_MAP

logger = logging.getLogger(__name__)


class PackageResolver:
    """Resolves PyPI package distribution names to top-level import module names."""

    _cached_dist_to_modules: Optional[Dict[str, List[str]]] = None

    @classmethod
    def _get_installed_distribution_map(cls) -> Dict[str, List[str]]:
        """Inverts importlib.metadata.packages_distributions() to map dist_name -> [module_name]."""
        if cls._cached_dist_to_modules is not None:
            return cls._cached_dist_to_modules

        dist_to_modules: Dict[str, List[str]] = {}
        try:
            packages_dist = importlib.metadata.packages_distributions()
            for mod_name, dist_list in packages_dist.items():
                for dist in dist_list:
                    c_dist = canonicalize_name(dist)
                    if c_dist not in dist_to_modules:
                        dist_to_modules[c_dist] = []
                    if mod_name not in dist_to_modules[c_dist]:
                        dist_to_modules[c_dist].append(mod_name)
        except Exception as e:
            logger.warning("Could not read importlib.metadata.packages_distributions(): %s", e)

        cls._cached_dist_to_modules = dist_to_modules
        return cls._cached_dist_to_modules

    @classmethod
    def resolve(cls, package_name: str) -> ImportResolution:
        """Resolves a package distribution name to import module names.

        Priority order:
        1. Live installed metadata via importlib.metadata.packages_distributions()
        2. Static fallback mapping table
        3. Fallback to normalized package name (hyphens replaced by underscores)
        """
        c_name = canonicalize_name(package_name)

        # 1. Check live installed metadata
        installed_map = cls._get_installed_distribution_map()
        if c_name in installed_map and installed_map[c_name]:
            return ImportResolution(
                distribution_name=c_name,
                import_module_names=installed_map[c_name],
                resolution_confidence="high",
                method_used="metadata",
            )

        # 2. Check static mapping table
        if c_name in STATIC_PACKAGE_TO_MODULE_MAP:
            return ImportResolution(
                distribution_name=c_name,
                import_module_names=STATIC_PACKAGE_TO_MODULE_MAP[c_name],
                resolution_confidence="high",
                method_used="static_map",
            )

        # 3. Fallback heuristic
        fallback_mod = c_name.replace("-", "_")
        logger.info(
            "Package '%s' not found in metadata or static map; falling back to module '%s' (low confidence)",
            package_name,
            fallback_mod,
        )
        return ImportResolution(
            distribution_name=c_name,
            import_module_names=[fallback_mod],
            resolution_confidence="low",
            method_used="fallback",
        )

