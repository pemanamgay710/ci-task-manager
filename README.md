# 🧠 Flask Task Manager

A lightweight **Task Manager** web application built using **Flask**, featuring:

- 🧾 **User Registration & Login** (Email + Username + Password)  
- 🔐 **JWT Authentication** (Secure cookie-based sessions, 20-minute expiry)  
- 🔑 **Forgot / Reset Password** (via email or console token in dev mode)  
- 🗂️ **Task Management** (Add, Edit, Delete your personal tasks)  
- 🧱 **SQLite** database for easy setup  
- ⚙️ **Continuous Integration** with GitHub Actions  
- 🐳 **Docker Support** for portable deployment  

---

## 🚀 Quick Start (Local Development)

### 1️⃣ Clone the Repository
- git clone https://github.com/pemanamgay710/ci-task-manager.git
- cd ci-task-manager

### Application Features
| Feature             | Description                                                            |
| ------------------- | ---------------------------------------------------------------------- |
| **Register**        | Create a new user account (email, username, password)                  |
| **Login**           | Secure JWT-based cookie session (auto-expiry in 20 mins)               |
| **Forgot Password** | Generate a reset token (sent via email / console)                      |
| **Reset Password**  | Safely reset user password using token                                 |
| **Dashboard**       | Add, edit, and delete your personal tasks                              |
| **Logout**          | Securely clear JWT cookies                                             |
| **SQLite**          | Lightweight, easy-to-use local database                                |
| **CI/CD**           | Runs tests, linting, and Docker build automatically via GitHub Actions |
| **Dockerized**      | Easily deploy anywhere using Docker                                    |

## 🐳Running the App with Docker
### Build the Docker Image

sudo docker build -t flask-task-manager:latest .

## Run the Container
sudo docker run -p 5000:5000 flask-task-manager:latest


# ☁️ Deploy via Docker Hub
### You can directly pull and run the image without building it:

sudo docker pull pemanamgay710/flask-task-manager:latest
sudo docker run -p 5000:5000 pemanamgay710/flask-task-manager:latest


# 🧱 Project Structure

Task Manager/
│
├── static/
│   └── style.css
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│
├── tests/
│   └── test_app.py
│
├── app.py
├── models.py
├── forms.py
├── requirements.txt
├── Dockerfile
├── .github/
│   └── workflows/
│       └── ci.yml
└── README.md


# 🧑‍💻 Technologies Used

| Category             | Technology                  |
| -------------------- | --------------------------- |
| **Backend**          | Flask (Python)              |
| **Database**         | SQLite                      |
| **Authentication**   | Flask-JWT-Extended          |
| **Email**            | Flask-Mail                  |
| **Frontend**         | HTML, CSS (Jinja templates) |
| **Testing**          | Pytest                      |
| **CI/CD**            | GitHub Actions              |
| **Containerization** | Docker                      |

# 👨‍💻 Author
Pema Namgay
💻 