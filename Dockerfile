FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy application code
COPY iam_policy_analyzer/ ./iam_policy_analyzer/

# Create volume mount point for policies
RUN mkdir -p /policies

# Set entrypoint
ENTRYPOINT ["iam-analyzer"]
CMD ["--help"]
