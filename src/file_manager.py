"""
File Manager Module
Handles file system operations and directory browsing
"""

import os
import stat
from pathlib import Path
from typing import List, Dict, Any
import mimetypes

class FileManager:
    def __init__(self):
        self.supported_extensions = {
            '.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', 
            '.csv', '.json', '.xml', '.log', '.sql', '.py', 
            '.js', '.html', '.css', '.md', '.rtf'
        }
    
    def list_files(self, directory: str, recursive: bool = False) -> List[Dict[str, Any]]:
        """
        List all files in a directory with metadata
        
        Args:
            directory: Path to directory
            recursive: Whether to scan recursively
            
        Returns:
            List of file information dictionaries
        """
        files = []
        
        try:
            path = Path(directory)
            if not path.exists():
                raise FileNotFoundError(f"Directory not found: {directory}")
                
            if not path.is_dir():
                raise NotADirectoryError(f"Path is not a directory: {directory}")
            
            # Get files based on recursive flag
            if recursive:
                pattern = "**/*"
                file_paths = path.glob(pattern)
            else:
                file_paths = path.iterdir()
            
            for file_path in file_paths:
                try:
                    if file_path.is_file():
                        file_info = self._get_file_info(file_path)
                        files.append(file_info)
                except (PermissionError, OSError):
                    # Skip files we can't access
                    continue
                    
        except Exception as e:
            raise Exception(f"Failed to list files: {str(e)}")
            
        return files
    
    def _get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """
        Get detailed information about a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with file information
        """
        try:
            stat_info = file_path.stat()
            
            # Get MIME type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            
            # Determine if file is likely to contain sensitive data
            is_text_file = self._is_text_file(file_path)
            
            return {
                'path': str(file_path.absolute()),
                'name': file_path.name,
                'size': stat_info.st_size,
                'modified': stat_info.st_mtime,
                'type': mime_type or 'unknown',
                'extension': file_path.suffix.lower(),
                'is_text': is_text_file,
                'readable': os.access(file_path, os.R_OK),
                'writable': os.access(file_path, os.W_OK),
                'permissions': oct(stat_info.st_mode)[-3:]
            }
            
        except Exception as e:
            return {
                'path': str(file_path.absolute()),
                'name': file_path.name,
                'size': 0,
                'modified': 0,
                'type': 'unknown',
                'extension': file_path.suffix.lower(),
                'is_text': False,
                'readable': False,
                'writable': False,
                'permissions': '000',
                'error': str(e)
            }
    
    def _is_text_file(self, file_path: Path) -> bool:
        """
        Determine if a file is likely a text file that can be scanned
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file is likely text-based
        """
        # Check extension
        if file_path.suffix.lower() in self.supported_extensions:
            return True
            
        # Try to read first few bytes to detect text
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                
            # Check for null bytes (binary indicator)
            if b'\x00' in chunk:
                return False
                
            # Try to decode as text
            try:
                chunk.decode('utf-8')
                return True
            except UnicodeDecodeError:
                try:
                    chunk.decode('latin-1')
                    return True
                except UnicodeDecodeError:
                    return False
                    
        except (PermissionError, OSError):
            return False
    
    def get_directory_size(self, directory: str) -> int:
        """
        Calculate total size of directory
        
        Args:
            directory: Path to directory
            
        Returns:
            Total size in bytes
        """
        total_size = 0
        
        try:
            for dirpath, dirnames, filenames in os.walk(directory):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(file_path)
                    except (PermissionError, OSError):
                        continue
                        
        except Exception:
            pass
            
        return total_size
    
    def is_sensitive_filename(self, filename: str) -> bool:
        """
        Quick check if filename suggests sensitive content
        
        Args:
            filename: Name of the file
            
        Returns:
            True if filename suggests sensitive data
        """
        sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'credential',
            'ssn', 'social', 'tax', 'bank', 'account', 'credit',
            'personal', 'confidential', 'private', 'sensitive',
            'backup', 'wallet', 'financial', 'medical', 'health'
        ]
        
        filename_lower = filename.lower()
        return any(keyword in filename_lower for keyword in sensitive_keywords)