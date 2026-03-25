from celery import Celery

celery = Celery(
    'worker',
    broker='redis://redis:6379/0',
    backend='redis://redis:6379/1'
)

@celery.task(name='scan_task')
def scan_task(target, profile='recon'):
    return {
        "target": target,
        "profile": profile,
        "status": "completed",
        "summary": f"Placeholder scan for {target} completed"
    }
