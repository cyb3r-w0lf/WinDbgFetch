#!/usr/bin/env python3
"""
WinDbg Downloader - Python implementation (colorful stdout)
Fetches, downloads, and extracts the latest WinDbg from Microsoft Store
Launches it once Download complete
"""

import os
import sys
import platform
import subprocess
import tempfile
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Tuple
import requests
import zipfile
import time
import threading
import itertools
import signal



#======================================================================
#                           UTILITIES                                 #
#======================================================================

# CTRL+C HANDLER
def handle_sigint(sig, frame):
    print(Fore.RED + Style.BRIGHT + "\n❌ Script interrupted by user (Ctrl+C). Exiting...")
    sys.exit(1)

signal.signal(signal.SIGINT, handle_sigint)


# SPINNER
class Spinner:
    def __init__(self, message="Working..."):
        self.message = message
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        spinner_cycle = itertools.cycle(["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        while not self.stop_event.is_set():
            sys.stdout.write(f"\r{self.message} {next(spinner_cycle)}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r")  # clear line

    def start(self):
        self.stop_event.clear()
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join()

# COLOR OUTPUT
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
except Exception:
    # Fallback no-op colors if colorama not installed
    class _Dummy:
        RESET_ALL = ""
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = NORMAL = RESET_ALL = ""
    Fore = Fore()
    Style = Style()

# Small utility for consistent colored printing
def cprint(text: str,
           color: str = Fore.WHITE,
           style: str = Style.NORMAL,
           symbol: str = ""):
    """Colored print with optional symbol, auto-reset via colorama"""
    prefix = f"{style}{color}{symbol} " if symbol else f"{style}{color}"
    print(f"{prefix}{text}{Style.RESET_ALL}")

# Slightly fancier status printers
def info(msg: str):
    cprint(msg, Fore.CYAN, Style.BRIGHT, "🔍")

def success(msg: str):
    cprint(msg, Fore.GREEN, Style.BRIGHT, "✅")

def warn(msg: str):
    cprint(msg, Fore.YELLOW, Style.BRIGHT, "⚠️")

def error(msg: str):
    cprint(msg, Fore.RED, Style.BRIGHT, "❌")

class StrError(Exception):
    """Custom exception for string errors"""
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)



#======================================================================
#                         MAIN FUNCTIONS                              #
#======================================================================



def get_bundle_uri() -> Tuple[str, str]:
    """Get the bundle URI and version from Microsoft's download page"""
    url = "https://aka.ms/windbg/download"
    
    info("Fetching WinDbg download information...")
    
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        
        success("Successfully retrieved AppInstaller file")
        info(f"Final URL: {resp.url}")
        print()  # spacing
        
        info("================ Parsing XML ==================")
        text = resp.text
        
        # Parse the XML
        root = ET.fromstring(text)
        info(f"Root tag: {root.tag}")
        
        # The root should be AppInstaller
        if not root.tag.endswith('AppInstaller'):
            raise StrError(f"Unexpected root element: {root.tag}")
        
        # Get version from AppInstaller element
        version = root.get('Version')
        if not version:
            raise StrError("Could not find Version attribute on AppInstaller")
        
        # Find MainBundle element (it has a namespace)
        main_bundle = None
        for elem in root:
            if elem.tag.endswith('MainBundle'):
                main_bundle = elem
                break
        
        if main_bundle is None:
            # Try MainPackage as fallback
            for elem in root:
                if elem.tag.endswith('MainPackage'):
                    main_bundle = elem
                    break
        
        if main_bundle is None:
            raise StrError("Could not find MainBundle or MainPackage element")
        
        # Get URI from MainBundle
        uri = main_bundle.get('Uri')
        if not uri:
            raise StrError("Could not find Uri attribute on MainBundle")
        
        success(f"Found version: {version}")
        success(f"Found bundle URI: {uri}")
        info("============ Parsing XML Completed ============\n")
        
        return uri, version
        
    except requests.RequestException as e:
        raise StrError(f"Failed to fetch AppInstaller file: {e}")
    except ET.ParseError as e:
        raise StrError(f"Failed to parse AppInstaller XML: {e}")
    except Exception as e:
        raise StrError(f"Unexpected error: {e}")


def get_architecture() -> str:
    """Get the current system architecture"""
    arch = os.environ['PROCESSOR_ARCHITECTURE'].lower() #platform.machine().lower()
    if arch in ['amd64', 'x86_64']:
        return 'x64'
    elif arch in ['i386', 'i686', 'x86']:
        return 'x86'
    elif arch in ['arm64', 'aarch64']:
        return 'arm64'
    else:
        raise StrError(f"Unrecognized machine architecture: {arch}")


def get_filename_for_architecture_from_bundle_manifest(manifest: str, arch: str) -> Tuple[str, int]:
    """Parse bundle manifest to find the package for the given architecture"""
    try:
        root = ET.fromstring(manifest)
        
        # Find Package elements - handle namespaces
        for elem in root.iter():
            if elem.tag.endswith('Package'):
                package_arch = elem.get('Architecture')
                if package_arch == arch:
                    filename = elem.get('FileName')
                    offset_str = elem.get('Offset')
                    
                    if not filename:
                        raise StrError("FileName attribute missing on package")
                    if not offset_str:
                        raise StrError("Found package for architecture but it had no 'Offset' attribute")
                    
                    try:
                        offset = int(offset_str)
                        return filename, offset
                    except ValueError:
                        raise StrError("Invalid offset value")
        
        raise StrError("Could not find package for architecture")
        
    except ET.ParseError as e:
        raise StrError(f"Failed to parse manifest XML: {e}")


def verify_archive_signature(file_path: Path) -> bool:
    """Verify the digital signature of the archive using Windows WinTrust API"""
    if os.name != 'nt':
        warn("Signature verification only supported on Windows - skipping")
        return True

    spinner = Spinner(f"Verifying signature for {file_path.name}")
    spinner.start()
    
    try:
        import ctypes
        from ctypes import wintypes, Structure, POINTER, byref, c_void_p
        from ctypes.wintypes import DWORD, HANDLE, LPCWSTR
        
        # Load required Windows DLLs
        wintrust = ctypes.windll.wintrust
        kernel32 = ctypes.windll.kernel32
        
        # Define Windows structures
        class GUID(Structure):
            _fields_ = [
                ('Data1', DWORD),
                ('Data2', ctypes.c_ushort),
                ('Data3', ctypes.c_ushort),
                ('Data4', ctypes.c_ubyte * 8)
            ]
        
        class WINTRUST_FILE_INFO(Structure):
            _fields_ = [
                ('cbStruct', DWORD),
                ('pcwszFilePath', LPCWSTR),
                ('hFile', HANDLE),
                ('pgKnownSubject', POINTER(GUID))
            ]
        
        class WINTRUST_DATA(Structure):
            _fields_ = [
                ('cbStruct', DWORD),
                ('pPolicyCallbackData', c_void_p),
                ('pSIPClientData', c_void_p),
                ('dwUIChoice', DWORD),
                ('fdwRevocationChecks', DWORD),
                ('dwUnionChoice', DWORD),
                ('pFile', POINTER(WINTRUST_FILE_INFO)),
                ('dwStateAction', DWORD),
                ('hWVTStateData', HANDLE),
                ('pwszURLReference', LPCWSTR),
                ('dwProvFlags', DWORD),
                ('dwUIContext', DWORD),
                ('pSignatureSettings', c_void_p)
            ]
        
        # Constants
        WTD_UI_NONE = 2
        WTD_REVOKE_NONE = 0
        WTD_CHOICE_FILE = 1
        WTD_STATEACTION_VERIFY = 1
        ERROR_SUCCESS = 0
        
        # WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
        policy_guid = GUID()
        policy_guid.Data1 = 0x00AAC56B
        policy_guid.Data2 = 0xCD44
        policy_guid.Data3 = 0x11d0
        policy_guid.Data4 = (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
        
        # Initialize WINTRUST_FILE_INFO
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = str(file_path)
        file_info.hFile = None
        file_info.pgKnownSubject = None
        
        # Initialize WINTRUST_DATA
        wintrust_data = WINTRUST_DATA()
        wintrust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wintrust_data.pPolicyCallbackData = None
        wintrust_data.pSIPClientData = None
        wintrust_data.dwUIChoice = WTD_UI_NONE
        wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE
        wintrust_data.dwUnionChoice = WTD_CHOICE_FILE
        wintrust_data.pFile = ctypes.pointer(file_info)
        wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY
        wintrust_data.hWVTStateData = None
        wintrust_data.pwszURLReference = None
        wintrust_data.dwProvFlags = 0
        wintrust_data.dwUIContext = 0
        wintrust_data.pSignatureSettings = None
        
        # Define the WinVerifyTrust function signature
        wintrust.WinVerifyTrust.argtypes = [HANDLE, POINTER(GUID), c_void_p]
        wintrust.WinVerifyTrust.restype = ctypes.c_long
        
        # Call WinVerifyTrust
        # info(f"Verifying digital signature of {file_path.name}...")
        result = wintrust.WinVerifyTrust(None, byref(policy_guid), byref(wintrust_data))
        spinner.stop()


        # Interpret results
        if result == ERROR_SUCCESS:
            success("Digital signature verification PASSED")
            return True
        else:
            # Common error codes
            error_messages = {
                0x80096010: "TRUST_E_NOSIGNATURE - File is not signed",
                0x80096019: "TRUST_E_NOSIGNCERT - Certificate not found", 
                0x8009601E: "TRUST_E_UNTRUSTEDROOT - Root certificate not trusted",
                0x80096004: "TRUST_E_SUBJECT_FORM_UNKNOWN - Unknown subject type",
                0x80096001: "TRUST_E_PROVIDER_UNKNOWN - Unknown trust provider",
                0x800B0100: "CERT_E_EXPIRED - Certificate has expired",
                0x800B0101: "CERT_E_VALIDITYPERIODNESTING - Certificate validity period nesting",
                0x800B0102: "CERT_E_ROLE - Certificate role invalid",
                0x800B0109: "CERT_E_UNTRUSTEDROOT - Certificate chain to untrusted root",
            }
            
            error_msg = error_messages.get(result & 0xFFFFFFFF, f"Unknown error code: 0x{result & 0xFFFFFFFF:08X}")
            error(f"Digital signature verification FAILED: {error_msg}")
            
            # For debugging, show more details about common issues
            if (result & 0xFFFFFFFF) == 0x80096010:
                warn("→ This file is not digitally signed")
            elif (result & 0xFFFFFFFF) == 0x8009601E:
                warn("→ The certificate chain links to an untrusted root authority")
                warn("→ This might happen if the certificate is valid but not trusted on this system")
            
            return False
            
    except ImportError:
        warn("ctypes not available, skipping signature verification")
        return True
    except OSError as e:
        warn(f"Could not load Windows API (OSError: {e}), skipping signature verification")
        return True
    except Exception as e:
        error(f"Signature verification failed with error: {e}")
        warn("This might indicate the file is corrupted or the system doesn't support verification")
        # In case of unexpected errors, we'll be conservative and return False
        # But allow user to continue if they want
        user_input = input("Continue installation anyway? (y/N): ").strip().lower()
        return user_input in ['y', 'yes']


def extract_zip_archive(zip_path: Path, dest_dir: Path):
    """Extract a zip archive to destination directory"""
    # info("Extracting archive...")
    spinner = Spinner("Extracting Archive...")
    spinner.start()
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            # Security check for path traversal
            if '..' in member.filename or member.filename.startswith('/'):
                warn(f"Skipping potentially dangerous path: {member.filename}")
                continue
            
            # info(f"Extracting {member.filename}")
            zip_ref.extract(member, dest_dir)
    spinner.stop()
    success(f"Extracted in {dest_dir}")


def get_installed_version(install_dir: Path) -> Optional[str]:
    """Get the currently installed version"""
    version_file = install_dir / "version.txt"
    try:
        with open(version_file, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except (FileNotFoundError, IOError):
        return None


def set_installed_version(install_dir: Path, version: str):
    """Set the installed version"""
    version_file = install_dir / "version.txt"
    try:
        with open(version_file, 'w', encoding='utf-8') as f:
            f.write(version)
    except IOError as e:
        warn(f"Could not update installed version: {e}")


def download_and_extract_windbg(install_dir: Path, current_version: Optional[str] = None) -> Optional[str]:
    """Main function to download and extract WinDbg"""
    start_time = time.time()
    
    try:
        # Get bundle information
        bundle_uri, version = get_bundle_uri()
        
        # Check if we already have this version
        if current_version == version:
            info("No new version available")
            return version
        
        # Get system architecture
        arch = get_architecture()
        info(f"System architecture: {arch}")
        
        version_install_dir = install_dir / version
        version_install_dir.mkdir(parents=True, exist_ok=True)
        
        # Download the bundle
        spinner = Spinner("Downloading bundle...")
        spinner.start()
        response = requests.get(bundle_uri, stream=True)
        spinner.stop()
        response.raise_for_status()
        
        bundle_size = int(response.headers.get('content-length', 0))
        info(f"Bundle size: {bundle_size} bytes")
        
        # Save to temporary file with progress bar
        with tempfile.NamedTemporaryFile(delete=False, suffix='.msixbundle') as temp_file:
            temp_bundle_path = Path(temp_file.name)
            info(f"Saving temp_bundle_file in : {temp_bundle_path}")
            downloaded = 0
            
            # Initialize progress display
            bundle_size_mb = bundle_size / (1024 * 1024) if bundle_size > 0 else 0
            info(f"Bundle size: {bundle_size_mb:.1f} MB")
            print("Downloading: [", end="", flush=True)
            
            last_progress = 0
            for chunk in response.iter_content(chunk_size=8192):
                temp_file.write(chunk)
                downloaded += len(chunk)
                
                if bundle_size > 0:
                    progress = (downloaded / bundle_size) * 100
                    downloaded_mb = downloaded / (1024 * 1024)
                    
                    # Update progress bar every 2%
                    if int(progress / 2) > int(last_progress / 2):
                        # Calculate how many '=' to show (50 chars = 100%)
                        filled_chars = int(progress / 2)
                        
                        # Build progress bar string with colored filled area
                        filled = '=' * filled_chars
                        empty = ' ' * (50 - filled_chars)
                        # We color the filled portion green for visibility if colorama present
                        bar = f"\rDownloading: [{Fore.GREEN}{filled}{Style.RESET_ALL}{empty}] {progress:.1f}% ({downloaded_mb:.1f}/{bundle_size_mb:.1f} MB)"
                        print(bar, end="", flush=True)
                    
                    last_progress = progress
            
            print()  # New line after progress bar
        
        success("Download complete!")
        
        try:
            # Read the bundle as a zip file
            with zipfile.ZipFile(temp_bundle_path, 'r') as bundle_zip:
                info("Bundle contents:")
                for info_item in bundle_zip.infolist():
                    print(f"  {info_item.filename} ({info_item.file_size} bytes)")
                
                # Find the manifest
                manifest_content = None
                manifest_files = [
                    "AppxMetadata/AppxBundleManifest.xml",
                    "AppxManifest.xml",
                    "Package.appxmanifest"
                ]
                
                for manifest_file in manifest_files:
                    try:
                        with bundle_zip.open(manifest_file) as f:
                            manifest_content = f.read().decode('utf-8')
                            success(f"Found manifest: {manifest_file}")
                            break
                    except KeyError:
                        continue
                
                if not manifest_content:
                    warn("Could not find bundle manifest, trying to extract architecture-specific packages directly...")
                    
                    # Look for architecture-specific files
                    arch_patterns = {
                        'x64': ['x64', 'amd64'],
                        'x86': ['x86', 'win32'],
                        'arm64': ['arm64', 'aarch64']
                    }
                    
                    target_patterns = arch_patterns.get(arch, [arch])
                    
                    package_found = False
                    for file_info in bundle_zip.infolist():
                        filename_lower = file_info.filename.lower()
                        if any(pattern in filename_lower for pattern in target_patterns) and filename_lower.endswith(('.msix', '.appx')):
                            success(f"Found architecture package: {file_info.filename}")
                            
                            # Extract this package
                            package_path = version_install_dir / file_info.filename
                            with bundle_zip.open(file_info) as package_file:
                                with open(package_path, 'wb') as dest_file:
                                    shutil.copyfileobj(package_file, dest_file)
                            
                            info(f"Verifying certificates on {package_path}")
                            verify_start = time.time()
                            if not verify_archive_signature(package_path):
                                error("Signature verification failed!")
                                return None
                            verify_time = time.time() - verify_start
                            info(f"Time to verify: {verify_time:.2f}s")
                            
                            # Extract the package
                            info("Extracting MSIX package...")
                            extract_start = time.time()
                            extract_zip_archive(package_path, version_install_dir)
                            extract_time = time.time() - extract_start
                            info(f"Time to extract MSIX: {extract_time:.2f}s")
                            
                            # Clean up the package file
                            package_path.unlink()
                            package_found = True
                            break
                    
                    if not package_found:
                        raise StrError(f"Could not find package for architecture {arch}")
                        
                else:
                    # We have a manifest, use the original logic
                    package_filename, package_offset = get_filename_for_architecture_from_bundle_manifest(manifest_content, arch)
                    success(f"Found package for architecture: {package_filename}")
                    
                    # Extract the package
                    package_found = False
                    for file_info in bundle_zip.infolist():
                        if file_info.filename == package_filename:
                            package_found = True
                            info(f"Extracting package: {package_filename}")
                            
                            # Extract to version directory
                            package_path = version_install_dir / package_filename
                            with bundle_zip.open(file_info) as package_file:
                                with open(package_path, 'wb') as dest_file:
                                    shutil.copyfileobj(package_file, dest_file)
                            
                            info(f"Verifying certificates on {package_path}")
                            verify_start = time.time()
                            if not verify_archive_signature(package_path):
                                error("Signature verification failed!")
                                return None
                            verify_time = time.time() - verify_start
                            info(f"Time to verify: {verify_time:.2f}s")
                            
                            # Extract the package (it's an MSIX/ZIP file)
                            info("Extracting MSIX package...")
                            extract_start = time.time()
                            extract_zip_archive(package_path, version_install_dir)
                            extract_time = time.time() - extract_start
                            info(f"Time to extract MSIX: {extract_time:.2f}s")
                            
                            # Clean up the package file
                            package_path.unlink()
                            break
                    
                    if not package_found:
                        raise StrError(f"Could not find package {package_filename} in bundle")
        
        finally:
            # Clean up temporary bundle file
            try:
                temp_bundle_path.unlink()
            except Exception:
                pass
        
        total_time = time.time() - start_time
        success(f"Installed successfully. Time to install: {total_time:.2f}s")
        
        # Update version file
        set_installed_version(install_dir, version)
        
        return version
        
    except Exception as e:
        error(f"Installation failed: {e}")
        return None


def run_dbgx_shell(version_install_dir: Path, args: list):
    """Run DbgX.Shell.exe with the given arguments"""
    dbgx_path = version_install_dir / "DbgX.Shell.exe"
    
    if not dbgx_path.exists():
        error(f"DbgX.Shell.exe not found at {dbgx_path}")
        return False
    
    try:
        # Build command line
        cmd = [str(dbgx_path)] + args
        info(f"Executing: {' '.join(cmd)}")
        
        # Run the process
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
        
    except Exception as e:
        error(f"Could not launch DbgX.Shell.exe: {e}")
        return False


def main():
    """Main entry point"""
    # Get install directory (same directory as this script)
    script_path = Path(sys.argv[0]).resolve()
    install_dir = script_path.parent
    
    info(f"Install directory: {install_dir}")
    
    # Get current version
    current_version = get_installed_version(install_dir)
    
    if current_version:
        info(f"Current version: {current_version}")
        version_path = install_dir / current_version
        
        # Check if the installation exists
        dbgx_path = version_path / "DbgX.Shell.exe"
        if dbgx_path.exists():
            # Run in background thread while checking for updates
            args = sys.argv[1:]  # Pass through command line arguments
            
            def run_thread():
                run_dbgx_shell(version_path, args)
            
            thread = threading.Thread(target=run_thread)
            thread.start()
            
            # Check for updates in background
            info("Checking for updates in background...")
            download_and_extract_windbg(install_dir, current_version)
            
            # Wait for the main process to finish
            thread.join()
            return
    
    # No current version or installation missing, download and install
    info("No current installation found, downloading...")
    new_version = download_and_extract_windbg(install_dir, current_version)
    
    if new_version:
        version_install_dir = install_dir / new_version
        # Run DbgX.Shell.exe with command line arguments
        args = sys.argv[1:]
        run_dbgx_shell(version_install_dir, args)
    else:
        error("Installation failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()

