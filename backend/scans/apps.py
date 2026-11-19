from django.apps import AppConfig


class ScansConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scans"

    def ready(self):
        try:
            from django.conf import settings
            from django.utils.autoreload import autoreload_started

            def watch_engine_dirs(sender, **kwargs):
                project_root = getattr(settings, "PROJECT_ROOT", None)
                if project_root:
                    for engine_dir in ("security_engine", "ml_engine", "unified_engine"):
                        target_dir = project_root / engine_dir
                        if target_dir.is_dir():
                            sender.watch_dir(target_dir, "**/*.py")

            autoreload_started.connect(watch_engine_dirs, weak=False)
        except Exception:
            pass
