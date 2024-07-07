# Use the official Python image from the Docker Hub
FROM python:3.10

# Set environment variable to ensure the output is sent straight to terminal (without buffering)
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app


# Copy the requirements file into the container at /app
COPY requirements.txt /app/

# Install any dependencies specified in requirements.txt
RUN pip install -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . /app/

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Define the command to run the application with Django's SSL server
CMD ["python", "manage.py", "runsslserver", "127.0.0.1:9000"]
