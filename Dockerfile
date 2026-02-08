FROM python:3.12-slim

# Set working directory
WORKDIR /opt/xcel_itron2mqtt

# Copy only dependency file first (for better layer caching)
COPY xcel_itron2mqtt/requirements.txt .

# Install dependencies (this layer is cached unless requirements.txt changes)
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY xcel_itron2mqtt/ .

# Use ENTRYPOINT for Python (ensures it always runs correctly)
# CMD allows easy override: docker run <image> discover.py
ENTRYPOINT [ "python3", "-Wignore" ]
CMD [ "main.py" ]
