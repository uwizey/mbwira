from .models import AuditLog


def log_action(actor, action, obj=None, organization=None, details=None):
    """Record one important action. The only way the app writes audit rows."""
    if organization is None and obj is not None:
        organization = getattr(obj, "organization", None)

    return AuditLog.objects.create(
        organization=organization,
        actor=actor if getattr(actor, "is_authenticated", False) else None,
        action=action,
        object_type=obj._meta.label_lower if obj is not None else "",
        object_id=str(obj.pk) if obj is not None else "",
        details=details or {},
    )
