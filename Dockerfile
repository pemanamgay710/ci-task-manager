# Flask Task Manager Dockerfile

# 1️⃣ Base image
FROM python:3.10-slim

# 2️⃣ Working directory
WORKDIR /app

# 3️⃣ Copy dependency list
COPY requirements.txt .

# 4️⃣ Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 5️⃣ Copy the rest of the project
COPY . .

# 6️⃣ Expose Flask port
EXPOSE 5000

# 7️⃣ Environment setup
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

# 8️⃣ Start Flask app
CMD ["python", "app.py"]

