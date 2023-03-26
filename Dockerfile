# Pull base image
FROM python:3.10.6
RUN pip install --upgrade pip
# Set work directory
WORKDIR /

# Install dependencies
ADD . .

RUN pip install -r requirements.txt
EXPOSE 8000 

