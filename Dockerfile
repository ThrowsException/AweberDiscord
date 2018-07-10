# Use an official Python runtime as a parent image
FROM python:3.6-alpine3.7

RUN apk update && \
    apk add --virtual build-deps gcc python-dev musl-dev libffi-dev && \
    apk add postgresql-dev


# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

# Make port 80 available to the world outside this container
EXPOSE 8888

# Define environment variable
ENV NAME discord-aweber

# Run app.py when the container launches
CMD ["python", "app.py"]
