#!/usr/bin/env python3
"""
Build script to create a portable executable of the Secure Wipe application
This will create a standalone .exe file that can run on any Windows computer
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_requirements():
    """Check if all required packages are installed"""
    required_packages = [
        'pyinstaller',
        'openai',
        'cryptography', 
        'reportlab',
        'qrcode',
        'psutil',
        'Pillow'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("Missing required packages:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\nInstall them with:")
        print(f"pip install {' '.join(missing_packages)}")
        return False
    
    return True

def build_executable():
    """Build the portable executable"""
    print("🔨 Building Secure Wipe Portable Application...")
    
    # Define paths
    script_path = "secure_wipe_portable.py"
    dist_dir = "dist"
    build_dir = "build"
    
    # Clean previous builds
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)
    
    # PyInstaller command
    pyinstaller_cmd = [
        'pyinstaller',
        '--onefile',  # Create single executable
        '--windowed',  # Hide console window
        '--name', 'SecureWipePortable',
        '--add-data', 'src;src',  # Include src directory
        '--add-data', 'requirements.txt;.',  # Include requirements
        '--hidden-import', 'tkinter',
        '--hidden-import', 'tkinter.ttk',
        '--hidden-import', 'tkinter.filedialog',
        '--hidden-import', 'tkinter.messagebox',
        '--hidden-import', 'tkinter.simpledialog',
        '--clean',
        script_path
    ]
    
    try:
        print("Running PyInstaller...")
        result = subprocess.run(pyinstaller_cmd, check=True, capture_output=True, text=True)
        print("✅ Build completed successfully!")
        
        # Check if executable was created
        exe_path = Path(dist_dir) / "SecureWipePortable.exe"
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"📦 Executable created: {exe_path}")
            print(f"📏 Size: {size_mb:.1f} MB")
            
            # Create a simple README
            readme_path = Path(dist_dir) / "README.txt"
            with open(readme_path, 'w') as f:
                f.write("""
SECURE E-WASTE DATA WIPING PLATFORM - PORTABLE
==============================================

This is a standalone application for secure data wiping.

USAGE:
1. Double-click SecureWipePortable.exe to run
2. The application will open with a desktop interface
3. Click "Browse Your Computer" to select files/directories
4. Configure wipe settings and start secure deletion

FEATURES:
- Real file system access on your computer
- AI-powered sensitive data detection
- Multiple secure wipe patterns (DoD 5220.22-M)
- Digital certificates for compliance
- Comprehensive audit logging

SAFETY:
- System file protection enabled
- Multiple confirmation dialogs
- Secure overwrite algorithms
- Cannot recover deleted files

⚠️ WARNING: This permanently deletes files! Use with caution.

For technical support or questions, refer to the documentation.
""")
            
            print(f"📄 Created: {readme_path}")
            print("\n🎉 Your portable Secure Wipe application is ready!")
            print(f"\n📁 Find it in: {dist_dir}/")
            print("\nYou can now copy SecureWipePortable.exe to any computer and run it!")
            
        else:
            print("❌ Executable was not created")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
        print(f"Error output: {e.stderr}")
        return False
    
    return True

def create_installer():
    """Create a simple installer script"""
    installer_content = '''
@echo off
echo Installing Secure Wipe Portable...
echo.
echo This will copy the application to your Programs folder.
echo.
pause

if not exist "%PROGRAMFILES%\\SecureWipe" mkdir "%PROGRAMFILES%\\SecureWipe"
copy SecureWipePortable.exe "%PROGRAMFILES%\\SecureWipe\\"
copy README.txt "%PROGRAMFILES%\\SecureWipe\\"

echo.
echo Installation complete!
echo You can find Secure Wipe in: %PROGRAMFILES%\\SecureWipe\\
echo.
pause
'''
    
    installer_path = Path("dist") / "install.bat"
    with open(installer_path, 'w') as f:
        f.write(installer_content)
    
    print(f"📦 Created installer: {installer_path}")

def main():
    """Main build process"""
    print("🔒 Secure Wipe Portable - Build Tool")
    print("=" * 40)
    
    # Check if we're in the right directory
    if not os.path.exists("secure_wipe_portable.py"):
        print("❌ Error: secure_wipe_portable.py not found")
        print("Please run this script from the project directory")
        return
    
    if not os.path.exists("src"):
        print("❌ Error: src directory not found")
        print("Please ensure the src directory with modules exists")
        return
    
    # Check requirements
    if not check_requirements():
        return
    
    # Build executable
    if build_executable():
        create_installer()
        print("\n✅ Build process completed successfully!")
        print("\nNext steps:")
        print("1. Test the executable on your computer")
        print("2. Copy it to other computers as needed")
        print("3. Use install.bat for easy installation")
    else:
        print("\n❌ Build process failed!")

if __name__ == "__main__":
    main()