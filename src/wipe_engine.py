"""
Secure Data Wiping Engine
Implements various secure deletion algorithms and patterns
"""

import os
import random
import hashlib
import time
from pathlib import Path
from typing import List, Dict, Any, Callable
import psutil
import threading

class WipeEngine:
    def __init__(self):
        self.wipe_patterns = {
            'zero': lambda size: b'\x00' * min(size, 1024 * 1024),  # 1MB chunks
            'random': lambda size: os.urandom(min(size, 1024 * 1024)),
            'dod': self._dod_pattern  # DoD 5220.22-M standard
        }
        
        # Progress callback
        self.progress_callback: Callable[[float], None] = lambda x: None
        
    def set_progress_callback(self, callback: Callable[[float], None]):
        """Set callback function for progress updates"""
        self.progress_callback = callback
        
    def wipe_files(self, file_paths: List[str], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Securely wipe specified files
        
        Args:
            file_paths: List of file paths to wipe
            config: Wipe configuration with passes, pattern, method
            
        Returns:
            Dictionary with operation results
        """
        results = {
            'operation': 'file_wipe',
            'config': config,
            'files_processed': [],
            'files_failed': [],
            'start_time': time.time(),
            'total_files': len(file_paths),
            'total_size': 0
        }
        
        try:
            passes = config.get('passes', 3)
            pattern_name = config.get('pattern', 'random')
            
            # Calculate total size for progress tracking
            total_size = 0
            valid_files = []
            
            for file_path in file_paths:
                try:
                    path = Path(file_path)
                    if path.exists() and path.is_file():
                        size = path.stat().st_size
                        total_size += size * passes  # Multiply by passes for progress calc
                        valid_files.append((str(path), size))
                    else:
                        results['files_failed'].append({
                            'path': file_path,
                            'error': 'File not found or not accessible'
                        })
                except Exception as e:
                    results['files_failed'].append({
                        'path': file_path,
                        'error': str(e)
                    })
            
            results['total_size'] = total_size
            processed_size = 0
            
            # Wipe each file
            for file_path, file_size in valid_files:
                try:
                    file_result = self._wipe_single_file(file_path, passes, pattern_name)
                    file_result['original_size'] = file_size
                    results['files_processed'].append(file_result)
                    
                    processed_size += file_size * passes
                    progress = 100.0 if total_size == 0 else (processed_size / total_size) * 100
                    self.progress_callback(min(100.0, progress))
                    
                except Exception as e:
                    results['files_failed'].append({
                        'path': file_path,
                        'error': str(e)
                    })
            
            results['end_time'] = time.time()
            results['duration'] = results['end_time'] - results['start_time']
            results['success'] = len(results['files_failed']) == 0
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            results['success'] = False
            return results
    
    def wipe_device(self, device_path: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform full device/directory wipe
        
        Args:
            device_path: Path to device or directory to wipe
            config: Wipe configuration
            
        Returns:
            Dictionary with operation results
        """
        results = {
            'operation': 'device_wipe',
            'config': config,
            'device_path': device_path,
            'files_processed': [],
            'files_failed': [],
            'start_time': time.time()
        }
        
        try:
            # Find all files in the device/directory
            all_files = []
            for root, dirs, files in os.walk(device_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        if os.path.isfile(file_path) and os.access(file_path, os.W_OK):
                            all_files.append(file_path)
                    except (PermissionError, OSError):
                        continue
            
            # Wipe all found files
            file_results = self.wipe_files(all_files, config)
            results.update(file_results)
            
            # Additional device-specific operations
            if config.get('wipe_free_space', True):
                self._wipe_free_space(device_path)
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            results['success'] = False
            return results
    
    def _wipe_single_file(self, file_path: str, passes: int, pattern_name: str) -> Dict[str, Any]:
        """
        Securely wipe a single file with multiple passes and security enhancements
        
        Args:
            file_path: Path to file to wipe
            passes: Number of overwrite passes
            pattern_name: Pattern to use for overwriting
            
        Returns:
            Dictionary with file wipe results
        """
        path = Path(file_path)
        original_size = path.stat().st_size
        
        result = {
            'path': file_path,
            'passes_completed': 0,
            'original_size': original_size,
            'pattern_used': pattern_name,
            'verification_hashes': [],
            'start_time': time.time(),
            'security_measures': []
        }
        
        try:
            # Security check: ensure file is within allowed scope
            if not self._is_safe_to_wipe(file_path):
                raise PermissionError(f"File outside safe wipe scope: {file_path}")
                
            # Store original attributes for clearing
            original_stat = path.stat()
            
            # Open file for writing
            with open(file_path, 'r+b') as f:
                for pass_num in range(passes):
                    # Seek to beginning for each pass
                    f.seek(0)
                    
                    # Generate pattern data
                    pattern_func = self.wipe_patterns.get(pattern_name, self.wipe_patterns['random'])
                    
                    # Write pattern in chunks with secure flush
                    bytes_written = 0
                    chunk_size = 64 * 1024  # 64KB chunks for better performance
                    hash_obj = hashlib.sha256()
                    
                    while bytes_written < original_size:
                        remaining = original_size - bytes_written
                        current_chunk_size = min(chunk_size, remaining)
                        
                        if pattern_name == 'dod':
                            chunk_data = self._dod_pattern(current_chunk_size, pass_num)
                        else:
                            chunk_data = pattern_func(current_chunk_size)
                        
                        # Ensure chunk is correct size
                        if len(chunk_data) > current_chunk_size:
                            chunk_data = chunk_data[:current_chunk_size]
                        elif len(chunk_data) < current_chunk_size:
                            chunk_data += b'\x00' * (current_chunk_size - len(chunk_data))
                        
                        f.write(chunk_data)
                        hash_obj.update(chunk_data)
                        bytes_written += len(chunk_data)
                        
                        # Force write every chunk for security
                        f.flush()
                        
                    # Force all data to disk after each pass
                    os.fsync(f.fileno())
                    
                    result['passes_completed'] += 1
                    result['verification_hashes'].append(hash_obj.hexdigest())
                    result['security_measures'].append(f"Pass {pass_num + 1}: fsync completed")
                
                # Truncate file to zero length
                f.truncate(0)
                f.flush()
                os.fsync(f.fileno())
            
            # Clear file attributes
            try:
                # Windows blocks rename/delete for files made mode 000.
                os.chmod(file_path, 0o600 if os.name == 'nt' else 0o000)
                result['security_measures'].append("File attributes cleared")
            except Exception:
                pass
            
            # Rename file to random name before deletion (filename wiping)
            random_name = self._generate_random_filename(path.parent)
            try:
                os.rename(file_path, random_name)
                file_path = random_name
                result['security_measures'].append("Filename randomized")
            except Exception:
                pass
            
            # Final deletion
            os.unlink(file_path)
            result['security_measures'].append("File unlinked")
            
            # Verify deletion
            if os.path.exists(file_path):
                raise Exception("File still exists after deletion")
            
            result['end_time'] = time.time()
            result['duration'] = result['end_time'] - result['start_time']
            result['success'] = True
            result['deleted'] = True
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            result['success'] = False
            result['deleted'] = False
            return result
    
    def _dod_pattern(self, size: int, pass_num: int = 0) -> bytes:
        """
        Generate DoD 5220.22-M compliant wipe pattern
        
        Args:
            size: Size of data to generate
            pass_num: Pass number (0-2 for 3-pass DoD)
            
        Returns:
            Bytes for overwriting
        """
        # DoD 5220.22-M 3-pass pattern:
        # Pass 1: Write 0x00
        # Pass 2: Write 0xFF  
        # Pass 3: Write random data
        
        patterns = [b'\x00', b'\xFF', None]  # None means random
        
        if pass_num < len(patterns) and patterns[pass_num] is not None:
            pattern_byte = patterns[pass_num]
            return pattern_byte * size
        else:
            # Random data for pass 3 or any additional passes
            return os.urandom(int(size))
    
    def _wipe_free_space(self, directory_path: str):
        """
        Attempt to wipe free space in a directory
        
        Args:
            directory_path: Path to directory
        """
        try:
            # Get free space
            statvfs = os.statvfs(directory_path)
            free_bytes = statvfs.f_frsize * statvfs.f_bavail
            
            # Don't try to fill more than 1GB or 80% of free space
            max_fill = min(free_bytes * 0.8, 1024 * 1024 * 1024)
            
            if max_fill > 1024 * 1024:  # Only if more than 1MB free
                temp_file = os.path.join(directory_path, f'.wipe_temp_{int(time.time())}')
                
                try:
                    with open(temp_file, 'wb') as f:
                        written = 0
                        chunk_size = 1024 * 1024  # 1MB chunks
                        
                        while written < max_fill:
                            remaining = min(chunk_size, max_fill - written)
                            f.write(os.urandom(remaining))
                            written += remaining
                            
                            # Yield to other processes
                            time.sleep(0.001)
                    
                    # Delete temp file
                    os.unlink(temp_file)
                    
                except Exception:
                    # Clean up temp file if it exists
                    try:
                        if os.path.exists(temp_file):
                            os.unlink(temp_file)
                    except Exception:
                        pass
                        
        except Exception:
            # Free space wiping is best effort
            pass
    
    def estimate_wipe_time(self, file_paths: List[str], passes: int) -> float:
        """
        Estimate time required for wiping operation
        
        Args:
            file_paths: List of files to wipe
            passes: Number of passes
            
        Returns:
            Estimated time in seconds
        """
        total_size = 0
        
        for file_path in file_paths:
            try:
                total_size += Path(file_path).stat().st_size
            except Exception:
                continue
        
        # Estimate based on typical disk write speed (50MB/s)
        # This is conservative for SSDs but realistic for HDDs
        write_speed = 50 * 1024 * 1024  # 50 MB/s
        
        total_bytes_to_write = total_size * passes
        estimated_time = total_bytes_to_write / write_speed
        
        # Add overhead (20% for file operations, fsync, etc.)
        return estimated_time * 1.2
    
    def verify_wipe(self, file_path: str) -> bool:
        """
        Verify that a file has been successfully wiped (deleted)
        
        Args:
            file_path: Path that should have been wiped
            
        Returns:
            True if file no longer exists
        """
        return not os.path.exists(file_path)
    
    def _is_safe_to_wipe(self, file_path: str) -> bool:
        """
        Check if file is safe to wipe (security measure)
        
        Args:
            file_path: Path to check
            
        Returns:
            True if safe to wipe
        """
        path = Path(file_path)
        
        # Resolve any symlinks
        try:
            resolved_path = path.resolve()
        except Exception:
            return False
        
        # Check for dangerous system paths
        dangerous_paths = [
            '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/lib', '/usr/lib',
            '/etc', '/boot', '/sys', '/proc', '/dev', '/root',
            '/var/log', '/var/lib', '/var/run', '/tmp/systemd',
            'C:\\Windows', 'C:\\Program Files', 'C:\\System32'
        ]
        
        resolved_str = str(resolved_path)
        for dangerous in dangerous_paths:
            if resolved_str.startswith(dangerous):
                return False
        
        # Don't allow wiping of critical files
        critical_files = [
            'kernel', 'vmlinuz', 'initrd', 'bootloader',
            'passwd', 'shadow', 'hosts', 'fstab'
        ]
        
        filename = resolved_path.name.lower()
        for critical in critical_files:
            if critical in filename:
                return False
        
        # Check if file is executable system binary
        if resolved_path.suffix in ['.exe', '.dll', '.sys', '.so']:
            return False
        
        return True
    
    def _generate_random_filename(self, directory: Path) -> str:
        """
        Generate random filename in the same directory
        
        Args:
            directory: Directory for the random filename
            
        Returns:
            Random filename path
        """
        import random
        import string
        
        # Generate random filename
        random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        return str(directory / random_name)