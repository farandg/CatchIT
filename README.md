# CATCHIT

This is a simplified Dockerized fork of the original ```finos/CatchIT``` for local or pipeline use.

## Usage
To use catchit, simply build the container, then run it while attaching the code you want to scan as a volume.  
For instance:
```bash
cd catchit
docker build -t catchit .
docker run -v "$(pwd):/app" catchit --scan-path /app
```
