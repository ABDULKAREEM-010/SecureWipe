"""
Audit Logger
Comprehensive logging system for compliance and tracking
"""

import json
import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import threading

class AuditLogger:
    def __init__(self, db_path: str = "audit_logs.db"):
        self.db_path = Path(db_path)
        self.lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for audit logs"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    user_info TEXT,
                    system_info TEXT,
                    operation_data TEXT,
                    result_summary TEXT,
                    integrity_hash TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_logs(timestamp)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_operation_type ON audit_logs(operation_type)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_operation_id ON audit_logs(operation_id)
            """)
    
    def log_operation(self, operation_type: str, operation_data: Dict[str, Any], 
                     user_info: Optional[Dict[str, Any]] = None) -> str:
        """
        Log an operation to the audit trail
        
        Args:
            operation_type: Type of operation (WIPE, SCAN, CONFIG, etc.)
            operation_data: Detailed operation data
            user_info: User information if available
            
        Returns:
            Log entry ID
        """
        timestamp = datetime.now().isoformat()
        operation_id = self._generate_operation_id(operation_type, timestamp)
        
        # Get system info
        system_info = self._get_system_info()
        
        # Create result summary
        result_summary = self._create_result_summary(operation_data)
        
        # Create integrity hash
        log_data = {
            'timestamp': timestamp,
            'operation_type': operation_type,
            'operation_id': operation_id,
            'operation_data': operation_data,
            'result_summary': result_summary
        }
        
        integrity_hash = self._generate_integrity_hash(log_data)
        
        # Insert into database
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO audit_logs 
                    (timestamp, operation_type, operation_id, user_info, 
                     system_info, operation_data, result_summary, integrity_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp,
                    operation_type,
                    operation_id,
                    json.dumps(user_info) if user_info else None,
                    json.dumps(system_info),
                    json.dumps(operation_data, default=str),
                    json.dumps(result_summary),
                    integrity_hash
                ))
        
        # Also write to JSON log file for backup
        self._write_json_log(log_data, integrity_hash)
        
        return operation_id
    
    def _generate_operation_id(self, operation_type: str, timestamp: str) -> str:
        """Generate unique operation ID"""
        data = f"{operation_type}_{timestamp}"
        return hashlib.md5(data.encode()).hexdigest()[:12].upper()
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for logging"""
        import platform
        import os
        
        try:
            import psutil
            memory_info = {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available
            }
            disk_info = {
                'total': psutil.disk_usage('/').total,
                'free': psutil.disk_usage('/').free
            }
        except Exception:
            memory_info = {}
            disk_info = {}
        
        return {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'python_version': platform.python_version(),
            'hostname': platform.node(),
            'cwd': os.getcwd(),
            'memory': memory_info,
            'disk': disk_info,
            'environment_vars': {
                k: v for k, v in os.environ.items() 
                if k.startswith(('PYTHON', 'PATH')) and 'SECRET' not in k
            }
        }
    
    def _create_result_summary(self, operation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of operation results"""
        summary = {
            'operation': operation_data.get('operation', 'unknown'),
            'success': operation_data.get('success', False),
            'duration': operation_data.get('duration', 0)
        }
        
        if 'files_processed' in operation_data:
            summary['files_processed'] = len(operation_data['files_processed'])
        
        if 'files_failed' in operation_data:
            summary['files_failed'] = len(operation_data['files_failed'])
        
        if 'total_size' in operation_data:
            summary['total_size'] = operation_data['total_size']
        
        if 'config' in operation_data:
            summary['config'] = operation_data['config']
        
        return summary
    
    def _generate_integrity_hash(self, log_data: Dict[str, Any]) -> str:
        """Generate integrity hash for tamper detection"""
        # Create deterministic representation
        hash_data = json.dumps(log_data, sort_keys=True, default=str)
        return hashlib.sha256(hash_data.encode()).hexdigest()
    
    def _write_json_log(self, log_data: Dict[str, Any], integrity_hash: str):
        """Write log entry to JSON file as backup"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"audit_{datetime.now().strftime('%Y_%m_%d')}.jsonl"
        
        log_entry = {
            **log_data,
            'integrity_hash': integrity_hash,
            'created_at': datetime.now().isoformat()
        }
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry, default=str) + '\n')
    
    def get_audit_logs(self, operation_type: Optional[str] = None, 
                      start_date: Optional[str] = None,
                      end_date: Optional[str] = None,
                      limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve audit logs with optional filtering
        
        Args:
            operation_type: Filter by operation type
            start_date: Start date for filtering (ISO format)
            end_date: End date for filtering (ISO format)
            limit: Maximum number of logs to return
            
        Returns:
            List of audit log entries
        """
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []
        
        if operation_type:
            query += " AND operation_type = ?"
            params.append(operation_type)
        
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
        
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            log_entry = dict(row)
            
            # Parse JSON fields
            for field in ['user_info', 'system_info', 'operation_data', 'result_summary']:
                if log_entry[field]:
                    try:
                        log_entry[field] = json.loads(log_entry[field])
                    except json.JSONDecodeError:
                        pass
            
            logs.append(log_entry)
        
        return logs
    
    def verify_log_integrity(self, log_id: int) -> bool:
        """
        Verify the integrity of a log entry
        
        Args:
            log_id: ID of the log entry to verify
            
        Returns:
            True if log entry is intact
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM audit_logs WHERE id = ?", (log_id,))
            row = cursor.fetchone()
        
        if not row:
            return False
        
        # Recreate the log data
        log_data = {
            'timestamp': row['timestamp'],
            'operation_type': row['operation_type'],
            'operation_id': row['operation_id'],
            'operation_data': json.loads(row['operation_data']) if row['operation_data'] else {},
            'result_summary': json.loads(row['result_summary']) if row['result_summary'] else {}
        }
        
        # Calculate expected hash
        expected_hash = self._generate_integrity_hash(log_data)
        
        return expected_hash == row['integrity_hash']
    
    def get_audit_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of audit logs
        
        Returns:
            Dictionary with audit statistics
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    operation_type,
                    COUNT(*) as count,
                    MIN(timestamp) as first_operation,
                    MAX(timestamp) as last_operation
                FROM audit_logs 
                GROUP BY operation_type
            """)
            
            operations = {}
            for row in cursor.fetchall():
                operations[row[0]] = {
                    'count': row[1],
                    'first_operation': row[2],
                    'last_operation': row[3]
                }
            
            # Total count
            cursor = conn.execute("SELECT COUNT(*) FROM audit_logs")
            total_logs = cursor.fetchone()[0]
            
            # Recent activity
            cursor = conn.execute("""
                SELECT COUNT(*) FROM audit_logs 
                WHERE datetime(timestamp) >= datetime('now', '-24 hours')
            """)
            recent_logs = cursor.fetchone()[0]
        
        return {
            'total_logs': total_logs,
            'recent_logs_24h': recent_logs,
            'operations': operations,
            'database_size': self.db_path.stat().st_size if self.db_path.exists() else 0
        }
    
    def export_audit_logs(self, output_path: str, format: str = 'json') -> str:
        """
        Export all audit logs to a file
        
        Args:
            output_path: Path for output file
            format: Export format ('json' or 'csv')
            
        Returns:
            Path to exported file
        """
        logs = self.get_audit_logs(limit=10000)  # Get all logs
        
        if format.lower() == 'json':
            with open(output_path, 'w') as f:
                json.dump(logs, f, indent=2, default=str)
        
        elif format.lower() == 'csv':
            import csv
            
            if logs:
                fieldnames = logs[0].keys()
                with open(output_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for log in logs:
                        # Convert complex fields to strings
                        row = {}
                        for k, v in log.items():
                            if isinstance(v, (dict, list)):
                                row[k] = json.dumps(v, default=str)
                            else:
                                row[k] = v
                        writer.writerow(row)
        
        return output_path