"""
AI-Powered Sensitive Data Detector
Uses OpenAI to identify sensitive information in files
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple
import mimetypes

# the newest OpenAI model is "gpt-5" which was released August 7, 2025.
# do not change this unless explicitly requested by the user
from openai import OpenAI

class SensitiveDataDetector:
    def __init__(self):
        # Initialize OpenAI client with error handling
        api_key = os.environ.get("OPENAI_API_KEY")
        self.openai_available = bool(api_key)
        
        if self.openai_available:
            try:
                self.openai_client = OpenAI(api_key=api_key)
                # Test connection with a minimal request
                self._test_openai_connection()
            except Exception as e:
                print(f"OpenAI initialization failed: {e}")
                self.openai_available = False
                self.openai_client = None
        else:
            self.openai_client = None
            print("Warning: No OpenAI API key found. Using regex-only detection.")
        
        # Regex patterns for quick pre-filtering
        self.patterns = {
            'ssn': re.compile(r'\b\d{3}-?\d{2}-?\d{4}\b'),
            'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'aadhaar': re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b'),
            'pan': re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b'),
            'passport': re.compile(r'\b[A-Z]\d{7}\b'),
            'bank_account': re.compile(r'\b\d{9,18}\b'),
            'routing_number': re.compile(r'\b\d{9}\b')
        }
        
        # File size limit for AI analysis (1MB)
        self.max_file_size = 1024 * 1024
    
    def _test_openai_connection(self):
        """Test OpenAI connection with a minimal request"""
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",  # Use more reliable model for testing
                messages=[{"role": "user", "content": "test"}],
                max_tokens=1
            )
            return True
        except Exception as e:
            print(f"OpenAI connection test failed: {e}")
            self.openai_available = False
            return False
        
    def analyze_file(self, file_path: str) -> float:
        """
        Analyze a file for sensitive data and return risk score
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        try:
            path = Path(file_path)
            
            # Skip if file doesn't exist or can't be read
            if not path.exists() or not os.access(path, os.R_OK):
                return 0.0
                
            # Skip large files
            if path.stat().st_size > self.max_file_size:
                return self._analyze_filename_only(path.name)
                
            # Quick filename check
            filename_risk = self._analyze_filename_only(path.name)
            
            # Read file content
            content = self._read_file_content(path)
            if not content:
                return filename_risk
                
            # Pre-filter with regex
            regex_risk = self._regex_analysis(content)
            
            # If regex found potential sensitive data, use AI for confirmation (if available)
            if (regex_risk > 0.3 or filename_risk > 0.5) and self.openai_available:
                ai_risk = self._ai_analysis(content, path.name)
                return max(regex_risk, ai_risk, filename_risk)
            
            # Boost regex risk if AI is not available and patterns found
            if not self.openai_available and regex_risk > 0.3:
                regex_risk = min(regex_risk * 1.2, 1.0)  # Slight boost for conservative detection
            
            return max(regex_risk, filename_risk)
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {str(e)}")
            return 0.0
    
    def _read_file_content(self, file_path: Path) -> str:
        """
        Read file content with multiple encoding attempts
        
        Args:
            file_path: Path to file
            
        Returns:
            File content as string or empty string if failed
        """
        encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    # Read first 50KB for analysis
                    content = f.read(50000)
                    return content
            except (UnicodeDecodeError, PermissionError):
                continue
                
        return ""
    
    def _analyze_filename_only(self, filename: str) -> float:
        """
        Analyze filename for sensitive keywords
        
        Args:
            filename: Name of the file
            
        Returns:
            Risk score based on filename
        """
        sensitive_keywords = {
            'high': ['password', 'secret', 'key', 'token', 'credential', 'ssn', 'tax', 'bank'],
            'medium': ['personal', 'confidential', 'private', 'account', 'financial', 'backup'],
            'low': ['user', 'profile', 'data', 'info', 'document']
        }
        
        filename_lower = filename.lower()
        
        # Check for high-risk keywords
        for keyword in sensitive_keywords['high']:
            if keyword in filename_lower:
                return 0.8
                
        # Check for medium-risk keywords
        for keyword in sensitive_keywords['medium']:
            if keyword in filename_lower:
                return 0.5
                
        # Check for low-risk keywords
        for keyword in sensitive_keywords['low']:
            if keyword in filename_lower:
                return 0.2
                
        return 0.0
    
    def _regex_analysis(self, content: str) -> float:
        """
        Use regex patterns to detect potential sensitive data
        
        Args:
            content: File content to analyze
            
        Returns:
            Risk score based on regex matches
        """
        max_risk = 0.0
        matches_found = []
        
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.findall(content)
            if matches:
                matches_found.append(pattern_name)
                
                # Assign risk scores based on pattern type
                if pattern_name in ['ssn', 'credit_card', 'aadhaar', 'pan']:
                    max_risk = max(max_risk, 0.9)
                elif pattern_name in ['bank_account', 'passport']:
                    max_risk = max(max_risk, 0.8)
                elif pattern_name in ['phone', 'email']:
                    max_risk = max(max_risk, 0.4)
                else:
                    max_risk = max(max_risk, 0.3)
        
        return max_risk
    
    def _ai_analysis(self, content: str, filename: str) -> float:
        """
        Use OpenAI to analyze content for sensitive information
        
        Args:
            content: File content to analyze
            filename: Name of the file
            
        Returns:
            Risk score from AI analysis
        """
        try:
            if not self.openai_available:
                return 0.0
                
            # Truncate content if too long
            if len(content) > 8000:
                content = content[:8000] + "... [truncated]"
            
            prompt = f"""Analyze the following file content for sensitive personal information.
            
Filename: {filename}

Content:
{content}

Identify if this content contains any of the following sensitive information:
- Social Security Numbers (SSN)
- Credit card numbers
- Bank account numbers
- Personal identification numbers (Aadhaar, PAN, Passport)
- Medical records or health information
- Financial statements or tax documents
- Authentication credentials (passwords, API keys, tokens)
- Personal addresses or contact information in bulk
- Employment or salary information
- Legal documents with personal details

Respond with a JSON object containing:
- "risk_score": a number between 0.0 and 1.0 (where 1.0 is highest risk)
- "detected_types": array of detected sensitive data types
- "confidence": confidence level between 0.0 and 1.0
- "reasoning": brief explanation of the assessment

Be conservative in assessment. False positives are better than false negatives for data security."""

            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",  # Use more available model
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in sensitive data identification. Analyze content carefully and provide accurate risk assessments."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            
            content = response.choices[0].message.content or "{}"
            result = json.loads(content)
            risk_score = float(result.get('risk_score', 0.0))
            confidence = float(result.get('confidence', 0.5))
            
            # Adjust risk score based on confidence
            adjusted_risk = risk_score * confidence
            
            return min(1.0, max(0.0, adjusted_risk))
            
        except Exception as e:
            print(f"AI analysis failed: {str(e)}")
            return 0.0
    
    def get_detailed_analysis(self, file_path: str) -> Dict[str, Any]:
        """
        Get detailed analysis results for a file
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Dictionary with detailed analysis results
        """
        try:
            path = Path(file_path)
            content = self._read_file_content(path)
            
            # Regex analysis
            regex_matches = {}
            for pattern_name, pattern in self.patterns.items():
                matches = pattern.findall(content)
                if matches:
                    regex_matches[pattern_name] = len(matches)
            
            # Overall risk score
            risk_score = self.analyze_file(file_path)
            
            return {
                'file_path': file_path,
                'risk_score': risk_score,
                'regex_matches': regex_matches,
                'file_size': path.stat().st_size,
                'is_analyzable': bool(content),
                'analysis_timestamp': json.dumps({"timestamp": "now"})  # Placeholder
            }
            
        except Exception as e:
            return {
                'file_path': file_path,
                'risk_score': 0.0,
                'error': str(e)
            }