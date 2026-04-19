FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy the project files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-config --default-index https://pypi.org/simple

# Copy the rest of the application
COPY . .

# Set the environment variable for the port
ENV PORT=9000

# Expose the port
EXPOSE 9000

# Command to run the application
CMD ["uv", "run", "server.py"]
