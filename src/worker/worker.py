from celery import Celery

celery = Celery(
    'worker',
    broker='redis://redis:6379/0'
)

@celery.task
def scan_task(target):
    return f"Scanning {target} completed"