try:
    from .definitions import BUILTIN_TEMPLATES, ScanTemplate, ToolChainStep
    from .registry import template_registry
except Exception:
    from templates.definitions import BUILTIN_TEMPLATES, ScanTemplate, ToolChainStep
    from templates.registry import template_registry

__all__ = ["BUILTIN_TEMPLATES", "ScanTemplate", "ToolChainStep", "template_registry"]
