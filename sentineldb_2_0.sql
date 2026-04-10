-- =====================================================================================
-- SentinelDB 2.0 - Database Creation Script
-- Description: Advanced Schema, Procedures, and Triggers for Breach Impact & Exposure
-- Author: Senior Database Architect
-- =====================================================================================

CREATE DATABASE IF NOT EXISTS SentinelDB_V2;
USE SentinelDB_V2;

-- -------------------------------------------------------------------------------------
-- 1) SCHEMA DESIGN (3NF)
-- -------------------------------------------------------------------------------------

DROP TABLE IF EXISTS Security_Audit_Log;
DROP TABLE IF EXISTS Permissions_Bridge;
DROP TABLE IF EXISTS Columns_Catalog;
DROP TABLE IF EXISTS Data_Assets;
DROP TABLE IF EXISTS Users;
DROP TABLE IF EXISTS Departments;
DROP TABLE IF EXISTS Roles;

-- Roles Table
CREATE TABLE Roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE
) ENGINE=InnoDB;

-- Departments Table
CREATE TABLE Departments (
    department_id INT AUTO_INCREMENT PRIMARY KEY,
    department_name VARCHAR(100) NOT NULL UNIQUE
) ENGINE=InnoDB;

-- Users Table
-- aggregate_risk_score updated via trigger
CREATE TABLE Users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(150) NOT NULL UNIQUE,
    role_id INT NOT NULL,
    department_id INT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    aggregate_risk_score INT NOT NULL DEFAULT 0,
    CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES Roles(role_id) ON DELETE RESTRICT,
    CONSTRAINT fk_users_dept FOREIGN KEY (department_id) REFERENCES Departments(department_id) ON DELETE RESTRICT,
    CONSTRAINT chk_user_status CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED'))
) ENGINE=InnoDB;

-- Security_Audit_Log Table
CREATE TABLE Security_Audit_Log (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action_taken VARCHAR(100) NOT NULL,
    action_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    details VARCHAR(255),
    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Data_Assets Table
CREATE TABLE Data_Assets (
    asset_id INT AUTO_INCREMENT PRIMARY KEY,
    system_name VARCHAR(100) NOT NULL,
    database_name VARCHAR(100) NOT NULL,
    table_name VARCHAR(100) NOT NULL
) ENGINE=InnoDB;

-- Columns_Catalog Table
CREATE TABLE Columns_Catalog (
    column_id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    data_type VARCHAR(50) NOT NULL,
    sensitivity_level INT NOT NULL,
    description TEXT,
    CONSTRAINT fk_columns_asset FOREIGN KEY (asset_id) REFERENCES Data_Assets(asset_id) ON DELETE CASCADE,
    CONSTRAINT chk_sensitivity CHECK (sensitivity_level BETWEEN 1 AND 5)
) ENGINE=InnoDB;

-- Permissions_Bridge Table
CREATE TABLE Permissions_Bridge (
    permission_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    column_id INT NOT NULL,
    access_level VARCHAR(50) NOT NULL,
    granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_permissions_user FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_permissions_column FOREIGN KEY (column_id) REFERENCES Columns_Catalog(column_id) ON DELETE CASCADE,
    CONSTRAINT uq_user_column UNIQUE (user_id, column_id)
) ENGINE=InnoDB;


-- -------------------------------------------------------------------------------------
-- 2) ADVANCED DBMS LOGIC
-- -------------------------------------------------------------------------------------

DELIMITER //

-- Trigger: trg_Calculate_Risk_On_Permission_Grant
-- Automatically updates a user's aggregate_risk_score when a permission is added.
CREATE TRIGGER trg_Calculate_Risk_On_Permission_Grant
AFTER INSERT ON Permissions_Bridge
FOR EACH ROW
BEGIN
    DECLARE v_sensitivity INT DEFAULT 0;
    
    -- Retrieve sensitivity level for the newly permitted column
    SELECT sensitivity_level INTO v_sensitivity
    FROM Columns_Catalog
    WHERE column_id = NEW.column_id;
    
    -- Add the sensitivity level to the user's aggregate_risk_score
    UPDATE Users
    SET aggregate_risk_score = aggregate_risk_score + v_sensitivity
    WHERE user_id = NEW.user_id;
END //

-- Stored Procedure: Get_Comprehensive_Impact_Report
-- Retuns sensitive data paths for a specific user using JOIN and GROUP BY
CREATE PROCEDURE Get_Comprehensive_Impact_Report(IN p_user_id INT)
BEGIN
    SELECT 
        u.username,
        u.aggregate_risk_score,
        d.department_name,
        a.database_name,
        a.table_name,
        GROUP_CONCAT(c.column_name ORDER BY c.column_name ASC SEPARATOR ', ') AS sensitive_columns_accessed,
        MAX(c.sensitivity_level) AS highest_sensitivity_in_table,
        COUNT(c.column_id) AS total_accessible_columns_in_table
    FROM Users u
    JOIN Departments d ON u.department_id = d.department_id
    JOIN Permissions_Bridge pb ON u.user_id = pb.user_id
    JOIN Columns_Catalog c ON pb.column_id = c.column_id
    JOIN Data_Assets a ON c.asset_id = a.asset_id
    WHERE u.user_id = p_user_id
    GROUP BY 
        u.username, 
        u.aggregate_risk_score, 
        d.department_name, 
        a.database_name, 
        a.table_name
    ORDER BY highest_sensitivity_in_table DESC;
END //

-- Stored Procedure: sp_Lockdown_User
-- Transaction-based procedure that revokes access and creates an audit log
CREATE PROCEDURE sp_Lockdown_User(IN p_user_id INT, IN p_reason VARCHAR(255))
BEGIN
    -- Declare SQL exception handler
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        -- Rollback on any error
        ROLLBACK;
        RESIGNAL;
    END;

    -- Start Atomic Transaction
    START TRANSACTION;
    
    -- Update the user's status
    UPDATE Users
    SET status = 'REVOKED'
    WHERE user_id = p_user_id;
    
    -- Generate security audit log
    INSERT INTO Security_Audit_Log (user_id, action_taken, action_timestamp, details)
    VALUES (p_user_id, 'LOCKDOWN', NOW(), p_reason);
    
    -- Commit the transaction
    COMMIT;
END //

DELIMITER ;


-- -------------------------------------------------------------------------------------
-- 3) REALISTIC DATA SEEDING (20+ Rows)
-- -------------------------------------------------------------------------------------

-- Insert Departments
INSERT INTO Departments (department_name) VALUES 
('Human Resources'), 
('Finance'), 
('Information Technology');

-- Insert Roles
INSERT INTO Roles (role_name) VALUES 
('Executive'), 
('Manager'), 
('Analyst'), 
('Administrator');

-- Insert Users (Risk score is 0 initially, updated by trigger upon permission grants)
INSERT INTO Users (username, email, role_id, department_id, status) VALUES 
('rahul', 'rahul@company.com', 2, 1, 'ACTIVE'),     -- HR Manager
('arun', 'arun@company.com', 3, 1, 'ACTIVE'),     -- HR Analyst
('priya', 'priya@company.com', 1, 2, 'ACTIVE'),         -- Finance Executive
('ashok', 'ashok@company.com', 3, 2, 'ACTIVE'), -- Finance Analyst
('rohit', 'rohit@company.com', 4, 3, 'ACTIVE'),     -- IT Admin
('druv', 'druv@company.com', 3, 3, 'ACTIVE');   -- IT Analyst

-- Insert Data Assets
INSERT INTO Data_Assets (system_name, database_name, table_name) VALUES 
('HRIS', 'hr_db', 'employees'),
('HRIS', 'hr_db', 'payroll'),
('ERP', 'finance_db', 'transactions'),
('ERP', 'finance_db', 'customers'),
('ITSM', 'it_sys', 'network_logs');

-- Insert Columns Catalog (with sensitivity levels 1-5, PII Examples)
INSERT INTO Columns_Catalog (asset_id, column_name, data_type, sensitivity_level, description) VALUES 
(1, 'emp_id', 'INT', 1, 'Internal employee ID'),
(1, 'first_name', 'VARCHAR', 2, 'Employee first name'),
(1, 'last_name', 'VARCHAR', 2, 'Employee last name'),
(1, 'ssn', 'VARCHAR', 5, 'Social Security Number - Highly Sensitive PII'),
(1, 'dob', 'DATE', 4, 'Date of Birth - Sensitive PII'),
(2, 'bank_account_no', 'VARCHAR', 5, 'Direct deposit account number'),
(2, 'salary_amount', 'DECIMAL', 4, 'Employee compensation'),
(3, 'transaction_id', 'INT', 1, 'System transaction ID'),
(3, 'amount', 'DECIMAL', 2, 'Transaction monetary value'),
(4, 'customer_id', 'INT', 1, 'Internal customer ID'),
(4, 'credit_card_hash', 'VARCHAR', 5, 'Hashed credit card number Payment Data'),
(4, 'billing_address', 'VARCHAR', 3, 'Customer home billing address'),
(5, 'ip_address', 'VARCHAR', 2, 'Internal device IP address'),
(5, 'mac_address', 'VARCHAR', 3, 'Hardware MAC address');

-- Insert Permissions Bridge (Triggers trg_Calculate_Risk_On_Permission_Grant on each insert)
INSERT INTO Permissions_Bridge (user_id, column_id, access_level) VALUES 
(1, 1, 'READ_WRITE'),  -- jsmith (HR Manager) can see basic emp details
(1, 2, 'READ_WRITE'),
(1, 3, 'READ_WRITE'),
(1, 4, 'READ_WRITE'),  -- Access to SSN (+5 risk)
(1, 5, 'READ_WRITE'),  -- Access to DOB (+4 risk)
(2, 1, 'READ'),        -- awhite (HR Analyst)
(2, 2, 'READ'),
(2, 3, 'READ'),
(3, 8, 'READ'),        -- mdoe (Finance Exec)
(3, 9, 'READ'),
(3, 10, 'READ'),
(3, 11, 'READ'),       -- Access to CC Hash (+5 risk)
(4, 8, 'READ_WRITE'),  -- bjohnson (Finance Analyst)
(4, 9, 'READ_WRITE'),
(5, 13, 'READ_WRITE'), -- cadmin (IT Admin)
(5, 14, 'READ_WRITE'),
(5, 1, 'READ'),        -- Admin can see employee ID
(5, 4, 'READ');        -- Admin can see SSN (+5 risk)

-- =====================================================================================
-- End of Script
-- =====================================================================================
