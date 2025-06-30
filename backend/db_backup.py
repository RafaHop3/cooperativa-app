"""
Database Backup System with Encryption for cooperativa-app

This module handles regular encrypted backups of the SQLite database
and provides restoration capabilities in case of data loss.
"""

import os
import sqlite3
import shutil
import time
import datetime
import tarfile
import subprocess
import schedule
import threading
from pathlib import Path
from cryptography.fernet import Fernet
from loguru import logger
import argparse

# Configuration
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cooperativa.db')
BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.backup_key')
BACKUP_RETENTION_DAYS = 30
BACKUP_SCHEDULE_HOURS = 6  # Every 6 hours


def setup_backup_directory():
    """Create backup directory if it doesn't exist"""
    try:
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)
            logger.info(f"Backup directory created: {BACKUP_DIR}")
        return True
    except Exception as e:
        logger.error(f"Error creating backup directory: {str(e)}")
        return False


def generate_encryption_key():
    """Generate or load encryption key for backups"""
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, 'rb') as key_file:
                key = key_file.read()
                logger.info("Encryption key loaded from file")
            return key
        except Exception as e:
            logger.error(f"Error loading encryption key: {str(e)}")
    
    # Generate new key if it doesn't exist
    try:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        
        # Set restrictive permissions on the key file
        if os.name != 'nt':  # Unix-like systems
            os.chmod(KEY_FILE, 0o600)  # Owner read/write only
            
        logger.info("New encryption key generated and saved")
        return key
    except Exception as e:
        logger.error(f"Error generating encryption key: {str(e)}")
        return None


def backup_database():
    """Create encrypted backup of the database"""
    try:
        # Ensure backup directory exists
        setup_backup_directory()
        
        # Generate encryption key if needed
        key = generate_encryption_key()
        if not key:
            logger.error("Backup failed: Unable to generate/load encryption key")
            return False
        
        cipher = Fernet(key)
        
        # Create timestamp for filename
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"cooperativa_backup_{timestamp}.db"
        backup_path = os.path.join(BACKUP_DIR, backup_filename)
        
        # Create a backup copy with SQLite
        conn = sqlite3.connect(DB_PATH)
        backup_conn = sqlite3.connect(backup_path)
        
        # Perform backup using SQLite's backup function
        conn.backup(backup_conn)
        
        backup_conn.close()
        conn.close()
        
        # Create tar archive
        tar_path = f"{backup_path}.tar"
        with tarfile.open(tar_path, "w") as tar:
            tar.add(backup_path, arcname=os.path.basename(backup_path))
        
        # Read the tar file
        with open(tar_path, 'rb') as file:
            tar_data = file.read()
        
        # Encrypt the tar data
        encrypted_data = cipher.encrypt(tar_data)
        
        # Write encrypted data to file
        encrypted_path = f"{tar_path}.enc"
        with open(encrypted_path, 'wb') as file:
            file.write(encrypted_data)
        
        # Remove intermediate files
        os.remove(backup_path)
        os.remove(tar_path)
        
        logger.info(f"Database backup created and encrypted: {encrypted_path}")
        
        # Clean up old backups
        cleanup_old_backups()
        
        return True
    except Exception as e:
        logger.error(f"Error creating database backup: {str(e)}")
        return False


def restore_database(backup_file):
    """Restore database from encrypted backup"""
    try:
        # Load encryption key
        key = generate_encryption_key()
        if not key:
            logger.error("Restore failed: Unable to load encryption key")
            return False
        
        cipher = Fernet(key)
        
        # Read encrypted data
        with open(backup_file, 'rb') as file:
            encrypted_data = file.read()
        
        # Decrypt data
        tar_data = cipher.decrypt(encrypted_data)
        
        # Save decrypted tar data to a temporary file
        temp_tar = f"{backup_file}.tar.tmp"
        with open(temp_tar, 'wb') as file:
            file.write(tar_data)
        
        # Extract tar file
        temp_dir = os.path.join(BACKUP_DIR, "restore_temp")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)
        
        with tarfile.open(temp_tar, "r") as tar:
            tar.extractall(path=temp_dir)
        
        # Find the database file in the extracted directory
        db_files = [f for f in os.listdir(temp_dir) if f.endswith('.db')]
        if not db_files:
            logger.error("Restore failed: No database file found in backup")
            return False
        
        restore_db_path = os.path.join(temp_dir, db_files[0])
        
        # Create backup of current database before restoring
        backup_database()
        
        # Restore database
        # Close any open connections first
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.close()
        except:
            pass
        
        # Replace the current database with the restored one
        shutil.copy2(restore_db_path, DB_PATH)
        
        # Clean up
        shutil.rmtree(temp_dir)
        os.remove(temp_tar)
        
        logger.info(f"Database successfully restored from {backup_file}")
        return True
    except Exception as e:
        logger.error(f"Error restoring database: {str(e)}")
        return False


def cleanup_old_backups():
    """Remove backups older than BACKUP_RETENTION_DAYS"""
    try:
        if not os.path.exists(BACKUP_DIR):
            return
        
        current_time = time.time()
        retention_seconds = BACKUP_RETENTION_DAYS * 24 * 3600
        
        for filename in os.listdir(BACKUP_DIR):
            if filename.startswith("cooperativa_backup_") and filename.endswith(".tar.enc"):
                file_path = os.path.join(BACKUP_DIR, filename)
                file_mod_time = os.path.getmtime(file_path)
                
                if (current_time - file_mod_time) > retention_seconds:
                    os.remove(file_path)
                    logger.info(f"Removed old backup: {filename}")
        
        return True
    except Exception as e:
        logger.error(f"Error cleaning up old backups: {str(e)}")
        return False


def list_backups():
    """List all available backups with timestamps"""
    try:
        if not os.path.exists(BACKUP_DIR):
            print("No backups found.")
            return []
        
        backups = []
        for filename in os.listdir(BACKUP_DIR):
            if filename.startswith("cooperativa_backup_") and filename.endswith(".tar.enc"):
                file_path = os.path.join(BACKUP_DIR, filename)
                mod_time = os.path.getmtime(file_path)
                size = os.path.getsize(file_path)
                
                backup_date = datetime.datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
                size_mb = size / (1024 * 1024)
                
                backups.append({
                    "filename": filename,
                    "date": backup_date,
                    "size_mb": round(size_mb, 2)
                })
                
                print(f"- {filename}")
                print(f"  Created: {backup_date}")
                print(f"  Size: {round(size_mb, 2)} MB")
                print()
        
        return backups
    except Exception as e:
        logger.error(f"Error listing backups: {str(e)}")
        return []


def setup_scheduled_backups():
    """Set up scheduled backups at regular intervals"""
    schedule.every(BACKUP_SCHEDULE_HOURS).hours.do(backup_database)
    
    # Run as a separate thread
    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.daemon = True
    scheduler_thread.start()
    
    logger.info(f"Scheduled backups configured to run every {BACKUP_SCHEDULE_HOURS} hours")


def perform_test_backup():
    """Perform a test backup to ensure the system is working"""
    logger.info("Performing test backup...")
    result = backup_database()
    if result:
        logger.info("Test backup successful")
    else:
        logger.error("Test backup failed")
    return result


def main():
    """Main function for command line interface"""
    parser = argparse.ArgumentParser(description='Database Backup Utility')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--backup', action='store_true', help='Create a new backup')
    group.add_argument('--restore', metavar='FILE', help='Restore from specified backup file')
    group.add_argument('--list', action='store_true', help='List all available backups')
    group.add_argument('--schedule', action='store_true', help='Start scheduled backup daemon')
    
    args = parser.parse_args()
    
    if args.backup:
        backup_database()
    elif args.restore:
        restore_database(args.restore)
    elif args.list:
        list_backups()
    elif args.schedule:
        setup_scheduled_backups()
        print(f"Scheduled backups started, running every {BACKUP_SCHEDULE_HOURS} hours")
        # Keep the main thread alive
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("Scheduled backups stopped")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
