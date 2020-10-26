# Use Python on Alpine Linux as base image
FROM python:3.8-slim

# Create working directory
RUN mkdir -p /app
WORKDIR /app

# Copy app source
COPY . /app

# Define entrypoint of the app
ENTRYPOINT ["python3", "-u", "extractor.py"]
