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
COPY app/aks-kv-syncer.py .

# Set file permissions
RUN chmod 755 /app && chmod 700 aks-kv-syncer.py

# Switch to the non-privileged user
USER appuser

# Use ENTRYPOINT for flexible arguments
ENTRYPOINT ["python", "aks-kv-syncer.py"]