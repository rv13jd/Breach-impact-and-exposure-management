-- SentinelDB: Data Breach Impact & Exposure Management
-- MySQL DDL + DML Script

-- Create database and select it
CREATE DATABASE IF NOT EXISTS SentinelDB;
USE SentinelDB;

-- Drop tables in dependency order for repeatable execution
DROP TABLE IF EXISTS Permissions_Map;
DROP TABLE IF EXISTS Columns_Catalog;
DROP TABLE IF EXISTS Users;
DROP TABLE IF EXISTS Data_Assets;
DROP TABLE IF EXISTS Roles;

-- =========================================================
-- 1) Roles
-- =========================================================
CREATE TABLE Roles (
    role_id INT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE
) ENGINE=InnoDB;

-- =========================================================
-- 2) Users
-- =========================================================
CREATE TABLE Users (
    user_id INT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    role_id INT NOT NULL,
    risk_status VARCHAR(20) NOT NULL,
    total_risk_score DECIMAL(7,2) NOT NULL DEFAULT 0.00,
    CONSTRAINT fk_users_role
        FOREIGN KEY (role_id)
        REFERENCES Roles(role_id)
        ON DELETE CASCADE,
    CONSTRAINT chk_risk_status
        CHECK (risk_status IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_total_risk_score
        CHECK (total_risk_score >= 0)
) ENGINE=InnoDB;

-- =========================================================
-- 3) Data_Assets
-- =========================================================
CREATE TABLE Data_Assets (
    asset_id INT PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    db_name VARCHAR(100) NOT NULL
) ENGINE=InnoDB;

-- =========================================================
-- 4) Columns_Catalog
-- =========================================================
CREATE TABLE Columns_Catalog (
    column_id INT PRIMARY KEY,
    asset_id INT NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    sensitivity_level TINYINT NOT NULL,
    CONSTRAINT fk_columns_asset
        FOREIGN KEY (asset_id)
        REFERENCES Data_Assets(asset_id)
        ON DELETE CASCADE,
    CONSTRAINT chk_sensitivity_level
        CHECK (sensitivity_level BETWEEN 1 AND 5)
) ENGINE=InnoDB;

-- =========================================================
-- 5) Permissions_Map
-- =========================================================
CREATE TABLE Permissions_Map (
    map_id INT PRIMARY KEY,
    user_id INT NOT NULL,
    column_id INT NOT NULL,
    access_type VARCHAR(20) NOT NULL,
    CONSTRAINT fk_permissions_user
        FOREIGN KEY (user_id)
        REFERENCES Users(user_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_permissions_column
        FOREIGN KEY (column_id)
        REFERENCES Columns_Catalog(column_id)
        ON DELETE CASCADE,
    CONSTRAINT chk_access_type
        CHECK (access_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'MASKED_SELECT'))
) ENGINE=InnoDB;

-- =========================================================
-- Dummy Data Inserts
-- =========================================================

-- 3 Roles
INSERT INTO Roles (role_id, role_name) VALUES
(1, 'Security Analyst'),
(2, 'DBA'),
(3, 'Data Steward');

-- 5 Users
INSERT INTO Users (user_id, username, role_id, risk_status, total_risk_score) VALUES
(1, 'alice.sec', 1, 'HIGH', 78.50),
(2, 'bob.dba', 2, 'MEDIUM', 42.00),
(3, 'carol.steward', 3, 'LOW', 18.25),
(4, 'david.ops', 2, 'CRITICAL', 91.70),
(5, 'eva.audit', 1, 'MEDIUM', 55.40);

-- 3 Data Assets
INSERT INTO Data_Assets (asset_id, table_name, db_name) VALUES
(1, 'customer_profiles', 'crm_db'),
(2, 'payment_transactions', 'finance_db'),
(3, 'employee_records', 'hr_db');

-- 10 Columns Catalog entries with varying sensitivity (1-5)
INSERT INTO Columns_Catalog (column_id, asset_id, column_name, sensitivity_level) VALUES
(1, 1, 'customer_id', 2),
(2, 1, 'full_name', 3),
(3, 1, 'email_address', 4),
(4, 1, 'ssn', 5),
(5, 2, 'transaction_id', 2),
(6, 2, 'card_number', 5),
(7, 2, 'billing_zip', 3),
(8, 3, 'employee_id', 2),
(9, 3, 'salary', 4),
(10, 3, 'medical_info', 5);

-- 15 Permission Mappings
INSERT INTO Permissions_Map (map_id, user_id, column_id, access_type) VALUES
(1, 1, 1, 'SELECT'),
(2, 1, 3, 'SELECT'),
(3, 1, 4, 'MASKED_SELECT'),
(4, 2, 5, 'SELECT'),
(5, 2, 6, 'UPDATE'),
(6, 2, 7, 'SELECT'),
(7, 3, 2, 'SELECT'),
(8, 3, 9, 'MASKED_SELECT'),
(9, 3, 8, 'SELECT'),
(10, 4, 6, 'DELETE'),
(11, 4, 10, 'UPDATE'),
(12, 4, 4, 'SELECT'),
(13, 5, 3, 'SELECT'),
(14, 5, 7, 'INSERT'),
(15, 5, 10, 'MASKED_SELECT');
