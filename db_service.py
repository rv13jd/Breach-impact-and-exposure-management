import mysql.connector
from mysql.connector import Error
import pandas as pd
import os

class SentinelDBManager:
    """
    Database Manager class for SentinelDB logic layer operations.
    Handles secure connections and domain-specific analytical queries.
    """
    
    def __init__(self, host="localhost", database="SentinelDB_V2", user="root", password="root"):
        self.host = host
        self.database = database
        self.user = user
        self.password = password
        self.conn = None

    def connect(self):
        """Establishes a secure connection to the database."""
        try:
            # Connection timeout ensures we fail fast if the DB is unreachable
            self.conn = mysql.connector.connect(
                host=self.host,
                database=self.database,
                user=self.user,
                password=self.password,
                connection_timeout=5
            )
            if self.conn.is_connected():
                print("Successfully connected to SentinelDB.")
        except Error as e:
            print(f"Error while connecting to MySQL SentinelDB instance: {e}")
            self.conn = None
            raise

    def close(self):
        """Safely closes the database connection."""
        if self.conn is not None and self.conn.is_connected():
            self.conn.close()
            print("SentinelDB MySQL connection closed.")

    def fetch_risk_analytics(self):
        """
        Returns a summary of the system's overall risk status:
        - Count of compromised/revoked users
        - Top 5 highest risk users
        """
        if not self.conn or not self.conn.is_connected():
            raise Exception("Database connection is not established. Call connect() first.")
        
        try:
            cursor = self.conn.cursor(dictionary=True)
            
            # 1. Count of compromised users
            query_compromised = "SELECT COUNT(*) as compromised_count FROM Users WHERE status IN ('REVOKED', 'SUSPENDED')"
            cursor.execute(query_compromised)
            compromised_count = cursor.fetchone()['compromised_count']
            
            # 2. Top 5 highest risk users
            query_top_risk = """
                SELECT user_id, username, aggregate_risk_score, status
                FROM Users 
                ORDER BY aggregate_risk_score DESC 
                LIMIT 5
            """
            cursor.execute(query_top_risk)
            top_risk_users = cursor.fetchall()
            
            return {
                "compromised_users_count": compromised_count,
                "top_5_highest_risk_users": top_risk_users
            }
        except Error as e:
            print(f"Database error while fetching risk analytics: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error: {e}")
            return None
        finally:
            if 'cursor' in locals() and cursor is not None:
                cursor.close()

    def run_impact_simulation(self, user_id):
        """
        Executes the Get_Comprehensive_Impact_Report stored procedure 
        for a given user_id and converts the result into a Pandas DataFrame.
        """
        if not self.conn or not self.conn.is_connected():
            raise Exception("Database connection is not established. Call connect() first.")
        
        if user_id is None:
            raise ValueError("A valid user_id must be provided.")

        try:
            user_id = int(user_id)
        except ValueError:
            raise ValueError("user_id must be an integer.")

        try:
            # First, verify the user actually exists to provide a clearer error mechanism
            cursor_check = self.conn.cursor()
            cursor_check.execute("SELECT 1 FROM Users WHERE user_id = %s", (user_id,))
            exists = cursor_check.fetchone()
            cursor_check.close()
            
            if not exists:
                print(f"Warning: User ID {user_id} does not exist in the database.")
                return pd.DataFrame()

            # Execute the stored procedure
            cursor = self.conn.cursor()
            cursor.callproc('Get_Comprehensive_Impact_Report', [user_id])
            
            # Since stored procedures can return multiple result sets, we iterate over them
            results = []
            columns = []
            
            for result in cursor.stored_results():
                results.extend(result.fetchall())
                columns = [col[0] for col in result.description]
            
            # Load into DataFrame
            df = pd.DataFrame(results, columns=columns)
            return df
            
        except Error as e:
            print(f"Database error executing impact simulation for user {user_id}: {e}")
            # Reraise or return empty df based on design preference
            return pd.DataFrame() 
        except Exception as e:
            print(f"Unexpected error executing impact simulation: {e}")
            return pd.DataFrame()
        finally:
            if 'cursor' in locals() and cursor is not None:
                cursor.close()

    def trigger_lockdown(self, user_id, reason="Admin triggered lockdown via dashboard"):
        """
        Executes the sp_Lockdown_User stored procedure to immediately revoke
        access for a compromised user and logs the action.
        """
        if not self.conn or not self.conn.is_connected():
            raise Exception("Database connection is not established.")
        
        try:
            user_id = int(user_id)
        except ValueError:
            raise ValueError("user_id must be an integer.")

        try:
            cursor = self.conn.cursor()
            cursor.callproc('sp_Lockdown_User', [user_id, reason])
            self.conn.commit()
            return True
        except Error as e:
            print(f"Database error executing lockdown: {e}")
            return False
        finally:
            if 'cursor' in locals() and cursor is not None:
                cursor.close()
# Example usage (commented out for module usage):
# if __name__ == "__main__":
#     db = SentinelDBManager(password="your_root_password_here")
#     try:
#         db.connect()
#         analytics = db.fetch_risk_analytics()
#         print("Risk Analytics:", analytics)
#         
#         # Use a known user_id from the seeded data (e.g., 1 for jsmith)
#         impact_df = db.run_impact_simulation(user_id=1)
#         print("\nImpact Simulation DataFrame:")
#         print(impact_df)
#     except Exception as e:
#         print(e)
#     finally:
#         db.close()
