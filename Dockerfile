# Use an official Python runtime as a parent image
FROM python:3.9-slim
ARG CACHE_BUSTER
ARG BUILD_TIMESTAMP
ENV APP_BUILD_TIMESTAMP=${BUILD_TIMESTAMP}

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 50001 available to the world outside this container
EXPOSE 50001

# Define environment variable to ensure Python output is unbuffered
ENV PYTHONUNBUFFERED=1

# Run app.py when the container launches
CMD ["python", "app.py"]
