FROM python:3.11-alpine AS builder

# Create and use a non-privileged user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY app/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Second stage: Clean runtime image
FROM python:3.11-alpine
WORKDIR /app

# Create a non-privileged user in the final image
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy installed dependencies from the builder image
COPY --from=builder /install /usr/local

# Copy the application
COPY app/cert-manager-kv-syncer.py .

# Set file permissions
RUN chmod 755 /app && chmod 755 cert-manager-kv-syncer.py

# Switch to the non-privileged user
USER appuser

# Use ENTRYPOINT for flexible arguments
ENTRYPOINT ["python", "cert-manager-kv-syncer.py"]