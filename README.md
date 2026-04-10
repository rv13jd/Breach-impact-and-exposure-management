# 🛡️ SentinelDB: Breach Impact & Exposure Management

![SentinelDB Overview](https://img.shields.io/badge/Status-Active-brightgreen) ![Python Version](https://img.shields.io/badge/Python-3.x-blue) ![MySQL](https://img.shields.io/badge/Database-MySQL-orange)

## 📌 Overview

**SentinelDB** is a robust, Python-based graphical Command Center and Breach Simulation framework. Built on top of an advanced and secure MySQL architectural backend, it allows organizations to actively monitor user exposure, classify database sensitivity, simulate breaches, and execute real-time administrative lockdowns in the event of an identity compromise.

---

## 🔥 Core Features

- **🌐 Global Command Center**  
  A dark-themed Streamlit dashboard delivering real-time threat and risk telemetry. It tracks aggregate system health and the average risk score for operational identities alongside an interactive list of top priority risks.
  
- **🚨 Identity Breach Simulator**  
  Simulates the downstream impact if an internal employee/identity gets compromised. By hooking into database-level stored procedures, it accurately tracks which sensitive elements (PII like SSNs, Credit Card Hashes, access logs) would be exposed across multiple assets (HRIS, ERP, ITSM). The simulator returns Exposure Levels (Critical/Restricted/Internal).

- **🛑 One-Click Real-Time Containment**  
  Execute comprehensive administrative database lockdowns using atomic ACID transactional protocols. Triggers instant user privilege revocation and simultaneously generates immutable security audit logs within the Database.

- **📈 Dynamic Data Vizualizations**  
  Powered by `viz_engine.py`, metrics are translated into interactive visual objects: Plotly KPI Gauges, multicolored exposure distribution charts, and concentration Heatmaps utilizing Seaborn mapping.

- **⚙️ Advanced Backend Database (SentinelDB 2.0)**  
  Built entirely on a 3NF relational schema, enforcing data integrity via database-native solutions:
  - **Triggers**: Instantly calculate/aggregate user risk scores automatically on permission grants.
  - **Stored Procedures**: Used for deep JOIN computations (`Get_Comprehensive_Impact_Report`) and atomic event transactions (`sp_Lockdown_User`).

---

## 🛠️ Project Structure

- **`main_dashboard.py`**  
  The Streamlit entry point. Contains page structures and routing (Command Center, Simulator, System Audit) and sets the overall custom cybersecurity UX dark theme.

- **`db_service.py`**  
  Houses the `SentinelDBManager`. It acts as the secure middle layer abstracting database operations—establishing connections, generating analytics with raw SQL, executing Python-Pandas data transformations, and running database procedures.

- **`viz_engine.py`**  
  Independent visualizations utility module designed for Plotly/Seaborn graph generation based on the risk and exposure metrics.

- **`sentineldb_2_0.sql`**  
  The complete MySQL definition file containing table generation mapping, DDL schema creation, roles/permissions systems, stored procedures, triggers, and comprehensive seed data logic.

---

## 💻 Tech Stack

- **Frontend**: Streamlit
- **Backend Analytics**: Python 3, Pandas
- **Visualization Component**: Plotly Graph Objects, Seaborn, Matplotlib
- **Database Architecture**: MySQL (`mysql.connector`)

---

## 🚀 Getting Started

1. **Deploy the Database**
   Log into your local or remote MySQL environment and execute the provided `sentineldb_2_0.sql` script to deploy the database schema, internal DBMS logic, and mock users/permissions.
   ```bash
   mysql -u root -p < sentineldb_2_0.sql
   ```
2. **Ensure Credentials Mapped**
   Ensure your Python environment backend logic (in `db_service.py` / `main_dashboard.py`) contains the correct user credentials for your MySQL Root. Defaults are structured around local implementations.

3. **Install Dependencies**
   Install the required Python modules.
   ```bash
   pip install streamlit pandas mysql-connector-python plotly matplotlib seaborn
   ```

4. **Launch Command Center**
   Execute the visualization command center via Streamlit.
   ```bash
   streamlit run main_dashboard.py
   ```
