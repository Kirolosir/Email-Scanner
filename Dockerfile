# Container for the hosted status service (hosted_wsgi:application).
#
# This image serves status and nothing else. It carries no credential, and
# hosted_status.py imports nothing that could reach one, so a pulled image
# discloses code and no secrets. .dockerignore is what keeps that true; a
# guard test asserts it covers everything .gitignore protects.
#
# THE STATE VOLUME IS NOT OPTIONAL. The connection lifecycle relies on
# os.replace and fcntl.flock, and a container's own filesystem is discarded
# on every recycle. Mount a durable POSIX volume at HOSTED_STATE_ROOT - on
# Cloud Run that means Filestore (NFS); a GCS-FUSE mount cannot provide
# either primitive and the app refuses to boot on one rather than losing the
# connection record quietly.

FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY hosted-requirements.txt .
RUN pip install --no-cache-dir -r hosted-requirements.txt

# Only what the service actually imports. Copying the tree would pull in the
# Gmail and drafting modules, which this process has no business holding.
COPY hosted_wsgi.py hosted_status.py connection.py connection_expiry.py \
     private_runtime.py message_safety.py ./

# A fixed uid so the mounted volume can be owned to match. Running as root
# would let a compromise of the process rewrite its own code.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin service
USER 10001

EXPOSE 8080

# Unlike the broker, --workers is a resource choice here, not a correctness
# one: this service holds no cross-request state, so a second worker would be
# harmless. One is enough for a status endpoint, and Cloud Run scales by
# instance rather than by worker.
CMD exec gunicorn hosted_wsgi:application \
    --workers 1 --threads 8 \
    --bind 0.0.0.0:${PORT:-8080} \
    --timeout 30 \
    --access-logfile - --error-logfile -
