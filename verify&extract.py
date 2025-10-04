from pathlib import Path
import os, threading, itertools, sys, time, zipfile, shutil, argparse, signal
from typing import Optional, Tuple
import xml.etree.ElementTree as ET



# CTRL+C HANDLER
def handle_sigint(sig, frame):
    print(Fore.RED + Style.BRIGHT + "\n❌ Script interrupted by user (Ctrl+C). Exiting...")
    sys.exit(1)

signal.signal(signal.SIGINT, handle_sigint)


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


def extract_arch(zip_path: Path, dest_dir: Path):
    arch = get_architecture()
    start_time = time.time()

    try:
        with zipfile.ZipFile(zip_path, 'r') as bundle_zip:
            print("Bundle contents:")
            for info in bundle_zip.infolist():
                print(f"  {info.filename} ({info.file_size} bytes)")

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
                        print(f"Found manifest: {manifest_file}")
                        break
                except KeyError:
                    continue

            if not manifest_content:
                error("Could not find bundle manifest.")
                return

            # Parse available architectures
            root = ET.fromstring(manifest_content)
            packages = []
            for elem in root.iter():
                if elem.tag.endswith('Package'):
                    packages.append((elem.get('Architecture'), elem.get('FileName')))

            if not packages:
                raise StrError("No packages found in manifest.")

            print("\nAvailable Architectures in bundle:")
            for i, (pkg_arch, pkg_file) in enumerate(packages, 1):
                print(f"  [{i}] {pkg_arch}: {pkg_file}")

            # Prompt user for selection
            while True:
                try:
                    selection = int(input("\nSelect architecture to extract [1-{0}]: ".format(len(packages))))
                    if 1 <= selection <= len(packages):
                        arch, package_filename = packages[selection - 1]
                        break
                    else:
                        print("Invalid selection. Try again.")
                except ValueError:
                    print("Invalid input. Please enter a number.")

            print(f"\nSelected architecture: {arch}")
            print(f"Extracting package: {package_filename}")

            package_found = False
            for file_info in bundle_zip.infolist():
                if file_info.filename == package_filename:
                    package_found = True

                    temp_package_path = dest_dir / package_filename

                    with bundle_zip.open(file_info) as package_file:
                        with open(temp_package_path, 'wb') as dest_file:
                            shutil.copyfileobj(package_file, dest_file)

                    if not verify_archive_signature(temp_package_path):
                        error("Signature verification failed.")
                        return

                    arch_dir = dest_dir / arch
                    arch_dir.mkdir(parents=True,exist_ok=True)

                    extract_zip_archive(temp_package_path, arch_dir)

                    # Uncomment to delete after extraction
                    # temp_package_path.unlink()
                    break

            if not package_found:
                raise StrError(f"Could not find package file: {package_filename}")

    except Exception as e:
        error(f"Failed to extract architecture: {e}")

    total_time = time.time() - start_time
    success(f"Installed successfully in {total_time:.2f} seconds")


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


def main():

    parser = argparse.ArgumentParser(description="Extract architecture-specific MSIX package from bundle.")
    parser.add_argument("bundle",help="Path to the .msixbundle or .appxbundle file")
    parser.add_argument("-o","--output",help="Optional output Directory", default="extract")

    args=parser.parse_args()

    zip_path = Path(args.bundle).resolve()
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True,exist_ok=True)


    if not verify_archive_signature(zip_path):
        error("Signature verification failed!")
        return

    extract_arch(zip_path, output_dir)   

if __name__ == "__main__":
    main()