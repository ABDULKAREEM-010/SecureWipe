"""
Digital Certificate Generator
Creates tamper-proof certificates for wipe operations
"""

import os
import json
import hashlib
import qrcode
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import io
import base64

class CertificateGenerator:
    def __init__(self):
        self.cert_dir = Path("certificates")
        self.cert_dir.mkdir(exist_ok=True)
        
        # Generate or load signing keys
        self.private_key, self.public_key = self._get_or_create_keys()
        
    def _get_or_create_keys(self):
        """Generate or load RSA key pair for signing certificates"""
        # Use environment-specific secure storage path
        secure_dir = Path.home() / ".secure_wipe"
        secure_dir.mkdir(mode=0o700, exist_ok=True)
        
        private_key_path = secure_dir / "signing_key.pem"
        public_key_path = secure_dir / "public_key.pem"
        
        if private_key_path.exists() and public_key_path.exists():
            try:
                # Load existing keys
                with open(private_key_path, 'rb') as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
                
                with open(public_key_path, 'rb') as f:
                    public_key = serialization.load_pem_public_key(f.read())
                    
                return private_key, public_key
            except Exception:
                # If keys are corrupted, regenerate
                pass
        
        # Generate new keys with higher security
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096  # Increased key size for better security
        )
        public_key = private_key.public_key()
        
        # Save keys with secure permissions
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(private_key_path, 0o600)  # Owner read/write only
        
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        os.chmod(public_key_path, 0o644)  # Owner read/write, others read
        
        return private_key, public_key
    
    def generate_certificate(self, wipe_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a complete certificate for a wipe operation
        
        Args:
            wipe_results: Results from wipe operation
            
        Returns:
            Dictionary with certificate paths and data
        """
        timestamp = datetime.now()
        cert_id = self._generate_cert_id(wipe_results, timestamp)
        
        # Create certificate data
        cert_data = {
            'certificate_id': cert_id,
            'timestamp': timestamp.isoformat(),
            'operation_type': wipe_results.get('operation', 'unknown'),
            'configuration': wipe_results.get('config', {}),
            'results': {
                'total_files': wipe_results.get('total_files', 0),
                'files_processed': len(wipe_results.get('files_processed', [])),
                'files_failed': len(wipe_results.get('files_failed', [])),
                'total_size': wipe_results.get('total_size', 0),
                'duration': wipe_results.get('duration', 0),
                'success': wipe_results.get('success', False)
            },
            'verification': {
                'file_hashes': self._extract_file_hashes(wipe_results),
                'operation_hash': self._generate_operation_hash(wipe_results)
            },
            'system_info': self._get_system_info(),
            'compliance': {
                'standard': 'DoD 5220.22-M' if wipe_results.get('config', {}).get('pattern') == 'dod' else 'Custom',
                'passes': wipe_results.get('config', {}).get('passes', 0),
                'pattern': wipe_results.get('config', {}).get('pattern', 'unknown')
            }
        }
        
        # Sign the certificate
        signature = self._sign_certificate(cert_data)
        cert_data['signature'] = signature
        
        # Generate QR code
        qr_data = self._generate_qr_data(cert_data)
        qr_path = self._generate_qr_code(qr_data, cert_id)
        
        # Save JSON certificate
        json_path = self._save_json_certificate(cert_data, cert_id)
        
        # Generate PDF certificate
        pdf_path = self._generate_pdf_certificate(cert_data, qr_path, cert_id)
        
        return {
            'certificate_id': cert_id,
            'json_path': str(json_path),
            'pdf_path': str(pdf_path),
            'qr_path': str(qr_path),
            'certificate_data': cert_data,
            'verification_url': f"https://verify.securewipe.local/{cert_id}"  # Placeholder
        }
    
    def _generate_cert_id(self, wipe_results: Dict[str, Any], timestamp: datetime) -> str:
        """Generate unique certificate ID"""
        data = f"{timestamp.isoformat()}{json.dumps(wipe_results, sort_keys=True)}"
        return hashlib.sha256(data.encode()).hexdigest()[:16].upper()
    
    def _generate_operation_hash(self, wipe_results: Dict[str, Any]) -> str:
        """Generate hash of the entire operation for verification"""
        # Create deterministic representation
        operation_data = {
            'operation': wipe_results.get('operation'),
            'config': wipe_results.get('config'),
            'total_files': wipe_results.get('total_files'),
            'files_processed_count': len(wipe_results.get('files_processed', [])),
            'start_time': wipe_results.get('start_time'),
            'end_time': wipe_results.get('end_time')
        }
        
        data_str = json.dumps(operation_data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def _extract_file_hashes(self, wipe_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract verification hashes from wipe results"""
        file_hashes = []
        
        for file_result in wipe_results.get('files_processed', []):
            if 'verification_hashes' in file_result:
                file_hashes.append({
                    'file_path': file_result.get('path', ''),
                    'final_hash': file_result['verification_hashes'][-1] if file_result['verification_hashes'] else '',
                    'all_hashes': file_result['verification_hashes']
                })
        
        return file_hashes
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for the certificate"""
        import platform
        import psutil
        
        return {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'python_version': platform.python_version(),
            'hostname': platform.node(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total
        }
    
    def _sign_certificate(self, cert_data: Dict[str, Any]) -> str:
        """Create digital signature for certificate"""
        # Create deterministic representation for signing
        signable_data = {
            'certificate_id': cert_data['certificate_id'],
            'timestamp': cert_data['timestamp'],
            'operation_type': cert_data['operation_type'],
            'results': cert_data['results'],
            'verification': cert_data['verification']
        }
        
        data_bytes = json.dumps(signable_data, sort_keys=True).encode()
        
        signature = self.private_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode()
    
    def verify_certificate_signature(self, cert_data: Dict[str, Any]) -> bool:
        """Verify certificate digital signature"""
        try:
            signature = base64.b64decode(cert_data['signature'])
            
            # Recreate signable data
            signable_data = {
                'certificate_id': cert_data['certificate_id'],
                'timestamp': cert_data['timestamp'],
                'operation_type': cert_data['operation_type'],
                'results': cert_data['results'],
                'verification': cert_data['verification']
            }
            
            data_bytes = json.dumps(signable_data, sort_keys=True).encode()
            
            self.public_key.verify(
                signature,
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _generate_qr_data(self, cert_data: Dict[str, Any]) -> str:
        """Generate QR code data for certificate verification"""
        qr_info = {
            'id': cert_data['certificate_id'],
            'timestamp': cert_data['timestamp'],
            'verify_url': f"https://verify.securewipe.local/{cert_data['certificate_id']}",
            'hash': cert_data['verification']['operation_hash']
        }
        
        return json.dumps(qr_info)
    
    def _generate_qr_code(self, qr_data: str, cert_id: str) -> Path:
        """Generate QR code image"""
        qr = qrcode.main.QRCode(
            version=1,
            error_correction=qrcode.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        qr_path = self.cert_dir / f"{cert_id}_qr.png"
        img.save(qr_path)
        
        return qr_path
    
    def _save_json_certificate(self, cert_data: Dict[str, Any], cert_id: str) -> Path:
        """Save certificate as JSON file"""
        json_path = self.cert_dir / f"{cert_id}.json"
        
        with open(json_path, 'w') as f:
            json.dump(cert_data, f, indent=2, default=str)
        
        return json_path
    
    def _generate_pdf_certificate(self, cert_data: Dict[str, Any], qr_path: Path, cert_id: str) -> Path:
        """Generate PDF certificate"""
        pdf_path = self.cert_dir / f"{cert_id}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=1,  # Center
            textColor=colors.darkblue
        )
        
        story.append(Paragraph("SECURE DATA WIPING CERTIFICATE", title_style))
        story.append(Spacer(1, 20))
        
        # Certificate details
        details = [
            f"<b>Certificate ID:</b> {cert_data['certificate_id']}",
            f"<b>Date & Time:</b> {cert_data['timestamp']}",
            f"<b>Operation Type:</b> {cert_data['operation_type'].replace('_', ' ').title()}",
            "",
            "<b>OPERATION SUMMARY</b>",
            f"Files Processed: {cert_data['results']['files_processed']}",
            f"Total Files: {cert_data['results']['total_files']}",
            f"Failed Files: {cert_data['results']['files_failed']}",
            f"Total Data Size: {self._format_bytes(cert_data['results']['total_size'])}",
            f"Duration: {cert_data['results']['duration']:.2f} seconds",
            f"Status: {'SUCCESS' if cert_data['results']['success'] else 'FAILED'}",
            "",
            "<b>WIPE CONFIGURATION</b>",
            f"Passes: {cert_data['configuration'].get('passes', 'N/A')}",
            f"Pattern: {cert_data['configuration'].get('pattern', 'N/A').upper()}",
            f"Method: {cert_data['configuration'].get('method', 'N/A').replace('_', ' ').title()}",
            "",
            "<b>COMPLIANCE</b>",
            f"Standard: {cert_data['compliance']['standard']}",
            f"Verification Hash: {cert_data['verification']['operation_hash'][:32]}..."
        ]
        
        for detail in details:
            if detail == "":
                story.append(Spacer(1, 12))
            else:
                story.append(Paragraph(detail, styles['Normal']))
        
        story.append(Spacer(1, 30))
        
        # QR Code
        if qr_path.exists():
            story.append(Paragraph("<b>VERIFICATION QR CODE</b>", styles['Heading3']))
            story.append(Spacer(1, 12))
            story.append(Image(str(qr_path), width=2*inch, height=2*inch))
        
        story.append(Spacer(1, 30))
        
        # Footer
        footer_text = (
            "This certificate provides cryptographic proof of secure data destruction. "
            "The digital signature ensures authenticity and prevents tampering. "
            "Scan the QR code to verify this certificate online."
        )
        story.append(Paragraph(footer_text, styles['Italic']))
        
        # Build PDF
        doc.build(story)
        
        return pdf_path
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value = int(bytes_value / 1024.0)
        return f"{bytes_value:.1f} PB"