# Entropy and ML-based Network Attack Detection

## Description

This project focuses on detecting various network attacks, including **PortScan**, **DDoS**, and **DoS (HULK, SlowHTTPTest)**, using two primary approaches: **Machine Learning (ML)** and **Information Theory**.

- **Machine Learning Approach**: Utilizes a **Deep Neural Network (DNN)** built with **Keras**, achieving **93% precision** in classifying traffic as benign or malicious. However, it may face challenges with adapting to new, unseen attack types.

- **Information Theory Approach**: Employs **entropy** and **Huffman coding** to detect anomalies in network traffic. This method does not require training and is effective for **real-time detection** of sudden changes in traffic patterns.

The project compares these two methods, highlighting their strengths and weaknesses, and provides a comprehensive evaluation of their performance against different attack types.

> **Note**: Some files are massive. Please refer to the Drive link below to download all files:  
> [Google Drive Folder](https://drive.google.com/drive/folders/1zPcoCk3V0I2L33n6iyS57zzk_mRdSnnb?usp=sharing)

---

## Tools and Technologies

- **Kali Linux** – for attack simulation  
- **Scapy** – for packet manipulation  
- **MySQL** – data storage  
- **Django** – backend framework  
- **WebSocket, HTML, JavaScript, CSS** – for real-time visualization  
- **TensorFlow** – for ML models  
- **Python** – programming language

---

## Dataset

The dataset includes **benign traffic** and various attack types (e.g., **FTP-Patator, SSH-Patator, DoS, PortScan, DDoS**) collected over a week.

---

## Repository Structure

| Directory         | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `research`        | Contains data of all attacks tested for performance with entropy detection. |
| `kali`            | Includes scripts to generate packets from `data.csv`, to be run on Kali Linux or similar for simulation. |
| `ciphernet`       | Contains ciphernet and netpulse to run the application with data from the DB. |
| `network_traffic` | Script to capture packets, apply ML, calculate entropy, and store data in MySQL. |

---

## Installation

### 1. Create Database

```bash
mysql -u root -p
create database ciphernet_db;
```

### 2. Set up Environment

Create a `.env` file with the following content (fill in your DB credentials):

```env
DATABASE_ENGINE=django.db.backends.mysql
DATABASE_USER=your_username
DATABASE_PASSWORD=your_password
DATABASE_NAME=ciphernet_db
DATABASE_HOST=your_host
DATABASE_PORT=3306
```

### 3. Create a Virtual Environment

```bash
python -m venv venv
```

### 4. Activate the Virtual Environment

**On Windows:**
```bash
venv\Scripts\activate
```

**On Linux/Mac:**
```bash
source venv/bin/activate
```

### 5. Install Requirements

```bash
pip install -r requirements.txt
```

### 6. Run the Project

#### Run Packet Capturer:

```bash
cd network_traffic
python capteur.py
```

#### Run Application:

```bash
cd ..
python manage.py makemigrations netpulse
python manage.py migrate
python manage.py runserver
```

> Ensure the `.env` file is correctly configured with your database credentials.

---

## Usage

### Run Packet Capturer

```bash
cd network_traffic
python capteur.py
```

- Captures packets  
- Applies ML models  
- Calculates entropy  
- Stores results in MySQL

### Run Django Application

```bash
cd ..
python manage.py makemigrations netpulse
python manage.py migrate
python manage.py runserver
```

- Launches a real-time dashboard at:  
  **http://localhost:8000**

---

## Evaluation

| **Approach**         | **Metric**                     | **Value** |
|----------------------|--------------------------------|-----------|
| **Machine Learning** | Precision                      | 93%       |
|                      | Recall                         | 93%       |
|                      | F1-score                       | 93%       |
| **Information Theory** | PortScan Precision           | 0.81      |
|                      | DDoS Precision                 | 0.71      |
|                      | DoS HULK Precision             | 0.45      |
|                      | DoS SlowHTTPTest Precision     | 0.65      |

> These metrics indicate the effectiveness of each approach in detecting different types of attacks.

---

## Technologies

| **Category**      | **Tools**                     |
|------------------|-------------------------------|
| Machine Learning | TensorFlow, Keras             |
| Web Framework    | Django                        |
| Database         | MySQL                         |
| Scripting        | Python, Scapy                 |
| Operating System | Kali Linux                    |
| Frontend         | HTML, CSS, JavaScript, WebSocket |

---

## Additional Documentation

All files required for the project are available in this Drive folder:  
== > [Google Drive Folder](https://drive.google.com/drive/folders/1zPcoCk3V0I2L33n6iyS57zzk_mRdSnnb?usp=sharing)
