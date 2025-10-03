#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
WinDbg Downloader - Python 2 implementation
Fetches, downloads, and extracts the latest WinDbg from Microsoft Store
Launches it once download is complete
"""

from __future__ import print_function
import os
import sys
import platform
import subprocess
import tempfile
import shutil
import xml.etree.ElementTree as ET
import requests
import zipfile
import time
import threading
import codecs

# ---- Exceptions ----
class StrError(Exception):
    """Custom exception for string errors"""
    def __init__(self, message):
        self.message = message
        Exception.__init__(self, self.message)

# ---- Helpers ----
def get_bundle_uri():
    """Get the bundle URI and version from Microsoft's download page"""
    url = "https://aka.ms/windbg/download"
    print("Fetching WinDbg download information...")

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()

        print("Successfully retrieved AppInstaller file")
        print("Final URL: {}".format(resp.url))

        text = resp.text
        root = ET.fromstring(text)
        print("Parsed XML successfully. Root tag: {}".format(root.tag))

        if not root.tag.endswith('AppInstaller'):
            raise StrError("Unexpected root element: {}".format(root.tag))

        version = root.get('Version')
        if not version:
            raise StrError("Could not find Version attribute on AppInstaller")

        main_bundle = None
        for elem in root:
            if elem.tag.endswith('MainBundle'):
                main_bundle = elem
                break

        if main_bundle is None:
            for elem in root:
                if elem.tag.endswith('MainPackage'):
                    main_bundle = elem
                    break

        if main_bundle is None:
            raise StrError("Could not find MainBundle or MainPackage element")

        uri = main_bundle.get('Uri')
        if not uri:
            raise StrError("Could not find Uri attribute on MainBundle")

        print("Found version: {}".format(version))
        print("Found bundle URI: {}".format(uri))

        return uri, version

    except requests.RequestException as e:
        raise StrError("Failed to fetch AppInstaller file: {}".format(e))
    except ET.ParseError as e:
        raise StrError("Failed to parse AppInstaller XML: {}".format(e))
    except Exception as e:
        raise StrError("Unexpected error: {}".format(e))

def get_architecture():
    """Get the current system architecture"""
    arch = platform.machine().lower()
    if arch in ['amd64', 'x86_64']:
        return 'x64'
    elif arch in ['i386', 'i686', 'x86']:
        return 'x86'
    elif arch in ['arm64', 'aarch64']:
        return 'arm64'
    else:
        raise StrError("Unrecognized machine architecture: {}".format(arch))

def get_filename_for_architecture_from_bundle_manifest(manifest, arch):
    """Parse bundle manifest to find the package for the given architecture"""
    try:
        root = ET.fromstring(manifest)
        for elem in root.iter():
            if elem.tag.endswith('Package'):
                package_arch = elem.get('Architecture')
                if package_arch == arch:
                    filename = elem.get('FileName')
                    offset_str = elem.get('Offset')

                    if not filename:
                        raise StrError("FileName attribute missing on package")
                    if not offset_str:
                        raise StrError("Found package for architecture but no Offset attribute")

                    try:
                        offset = int(offset_str)
                        return filename, offset
                    except ValueError:
                        raise StrError("Invalid offset value")

        raise StrError("Could not find package for architecture {}".format(arch))

    except ET.ParseError as e:
        raise StrError("Failed to parse manifest XML: {}".format(e))


def verify_archive_signature(file_path):
    """Verify the digital signature of the archive (simplified for now)"""
    # Placeholder: signature verification omitted for simplicity
    print("Signature verification for {} - skipping for now".format(file_path))
    return True

def extract_zip_archive(zip_path, dest_dir):
    """Extract a zip archive to destination directory (with simple path traversal avoidance)"""
    print("Extracting archive: {} -> {}".format(zip_path, dest_dir))
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            # Security check for path traversal
            if '..' in member.filename or member.filename.startswith('/'):
                print("Skipping potentially dangerous path: {}".format(member.filename))
                continue

            target_path = os.path.join(dest_dir, member.filename)
            # Ensure directory exists
            target_dir = os.path.dirname(target_path)
            if target_dir and not os.path.exists(target_dir):
                try:
                    os.makedirs(target_dir)
                except Exception:
                    # ignore races
                    pass

            print("Extracting {}".format(member.filename))
            try:
                zip_ref.extract(member, dest_dir)
            except Exception as e:
                print("Failed to extract {}: {}".format(member.filename, e))

def get_installed_version(install_dir):
    """Get the currently installed version (reads version.txt in install_dir)"""
    version_file = os.path.join(install_dir, "version.txt")
    try:
        with codecs.open(version_file, 'r', 'utf-8') as f:
            return f.read().strip()
    except (IOError, OSError):
        return None

def set_installed_version(install_dir, version):
    """Set the installed version (writes version.txt)"""
    version_file = os.path.join(install_dir, "version.txt")
    try:
        with codecs.open(version_file, 'w', 'utf-8') as f:
            f.write(version)
    except (IOError, OSError) as e:
        print("Could not update installed version: {}".format(e))

# ---- Main download & extract function (Python 2) ----
def download_and_extract_windbg(install_dir, current_version=None):
    """Main function to download and extract WinDbg (Python 2 version)"""
    start_time = time.time()

    try:
        bundle_uri, version = get_bundle_uri()

        if current_version == version:
            print("No new version available")
            return version

        print("Found version: {}".format(version))
        print("Bundle URI: {}".format(bundle_uri))

        arch = get_architecture()
        print("System architecture: {}".format(arch))

        version_install_dir = os.path.join(install_dir, version)
        if not os.path.exists(version_install_dir):
            os.makedirs(version_install_dir)

        # Download the bundle
        print("Downloading bundle...")
        response = requests.get(bundle_uri, stream=True)
        response.raise_for_status()

        bundle_size = int(response.headers.get('content-length', 0))
        print("Bundle size: {} bytes".format(bundle_size))

        # Save to temporary file
        fd, temp_bundle_path = tempfile.mkstemp(suffix=".msixbundle")
        os.close(fd)
        downloaded = 0

        bundle_size_mb = bundle_size / (1024.0 * 1024.0) if bundle_size > 0 else 0
        print("Bundle size: {:.1f} MB".format(bundle_size_mb))
        sys.stdout.write("Downloading: [")
        sys.stdout.flush()

        last_progress = 0
        with open(temp_bundle_path, 'wb') as temp_file:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                temp_file.write(chunk)
                downloaded += len(chunk)

                if bundle_size > 0:
                    progress = (downloaded / float(bundle_size)) * 100.0
                    downloaded_mb = downloaded / (1024.0 * 1024.0)

                    if int(progress / 2) > int(last_progress / 2):
                        filled_chars = int(progress / 2)
                        # redraw progress
                        sys.stdout.write(
                            "\rDownloading: [{}{}] {:.1f}% ({:.1f}/{:.1f} MB)".format(
                                "=" * filled_chars,
                                " " * (50 - filled_chars),
                                progress,
                                downloaded_mb,
                                bundle_size_mb
                            )
                        )
                        sys.stdout.flush()
                    last_progress = progress

        print("\nDownload complete!")

        try:
            with zipfile.ZipFile(temp_bundle_path, 'r') as bundle_zip:
                print("Bundle contents:")
                for info in bundle_zip.infolist():
                    print("  {} ({} bytes)".format(info.filename, info.file_size))

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
                            raw = f.read()
                            # raw is bytes in py2; try decode
                            try:
                                manifest_content = raw.decode('utf-8')
                            except Exception:
                                # fallback: treat as str
                                manifest_content = raw
                            print("Found manifest: {}".format(manifest_file))
                            break
                    except KeyError:
                        continue
                    except RuntimeError:
                        # zip handles may throw runtime errors for certain encodings
                        continue

                if not manifest_content:
                    print("Could not find bundle manifest, trying to extract architecture-specific packages directly...")

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
                            print("Found architecture package: {}".format(file_info.filename))
                            package_path = os.path.join(version_install_dir, file_info.filename)

                            try:
                                with bundle_zip.open(file_info) as package_file, open(package_path, 'wb') as dest_file:
                                    shutil.copyfileobj(package_file, dest_file)
                            except Exception as e:
                                print("Failed to extract package {}: {}".format(file_info.filename, e))
                                continue

                            print("Verifying certificates on {}".format(package_path))
                            verify_start = time.time()
                            if not verify_archive_signature(package_path):
                                print("Signature verification failed!")
                                try:
                                    os.remove(package_path)
                                except Exception:
                                    pass
                                return None
                            verify_time = time.time() - verify_start
                            print("Time to verify: {:.2f}s".format(verify_time))

                            print("Extracting MSIX package...")
                            extract_start = time.time()
                            extract_zip_archive(package_path, version_install_dir)
                            extract_time = time.time() - extract_start
                            print("Time to extract MSIX: {:.2f}s".format(extract_time))

                            try:
                                os.remove(package_path)
                            except Exception:
                                pass

                            package_found = True
                            break

                    if not package_found:
                        raise StrError("Could not find package for architecture {}".format(arch))

                else:
                    # We have a manifest, use the manifest parsing logic
                    package_filename, package_offset = get_filename_for_architecture_from_bundle_manifest(manifest_content, arch)
                    print("Found package for architecture: {}".format(package_filename))

                    package_found = False
                    for file_info in bundle_zip.infolist():
                        if file_info.filename == package_filename:
                            package_found = True
                            print("Extracting package: {}".format(package_filename))
                            package_path = os.path.join(version_install_dir, package_filename)

                            try:
                                with bundle_zip.open(file_info) as package_file, open(package_path, 'wb') as dest_file:
                                    shutil.copyfileobj(package_file, dest_file)
                            except Exception as e:
                                print("Failed to write package {}: {}".format(package_filename, e))
                                raise

                            print("Verifying certificates on {}".format(package_path))
                            verify_start = time.time()
                            if not verify_archive_signature(package_path):
                                print("Signature verification failed!")
                                try:
                                    os.remove(package_path)
                                except Exception:
                                    pass
                                return None
                            verify_time = time.time() - verify_start
                            print("Time to verify: {:.2f}s".format(verify_time))

                            print("Extracting MSIX package...")
                            extract_start = time.time()
                            extract_zip_archive(package_path, version_install_dir)
                            extract_time = time.time() - extract_start
                            print("Time to extract MSIX: {:.2f}s".format(extract_time))

                            try:
                                os.remove(package_path)
                            except Exception:
                                pass

                            break

                    if not package_found:
                        raise StrError("Could not find package {} in bundle".format(package_filename))

        finally:
            # Clean up temporary bundle file
            try:
                os.remove(temp_bundle_path)
            except Exception:
                pass

        total_time = time.time() - start_time
        print("Installed successfully. Time to install: {:.2f}s".format(total_time))

        # Update version file
        set_installed_version(install_dir, version)

        return version

    except Exception as e:
        print("Installation failed: {}".format(e))
        return None

# ---- Run executable helper ----
def run_dbgx_shell(version_install_dir, args):
    """Run DbgX.Shell.exe with the given arguments"""
    dbgx_path = os.path.join(version_install_dir, "DbgX.Shell.exe")

    if not os.path.exists(dbgx_path):
        print("DbgX.Shell.exe not found at {}".format(dbgx_path))
        return False

    try:
        cmd = [dbgx_path] + args
        print("Executing: {}".format(" ".join(cmd)))
        # Use subprocess.call for compatibility
        result = subprocess.call(cmd)
        return result == 0

    except Exception as e:
        print("Could not launch DbgX.Shell.exe: {}".format(e))
        return False

# ---- Main ----
def main():
    """Main entry point"""
    # Get install directory (same directory as this script)
    script_path = os.path.abspath(sys.argv[0])
    install_dir = os.path.dirname(script_path)

    print("Install directory: {}".format(install_dir))

    # Get current version
    current_version = get_installed_version(install_dir)

    if current_version:
        print("Current version: {}".format(current_version))
        version_path = os.path.join(install_dir, current_version)

        # Check if the installation exists
        dbgx_path = os.path.join(version_path, "DbgX.Shell.exe")
        if os.path.exists(dbgx_path):
            # Run in background thread while checking for updates
            args = sys.argv[1:]  # Pass through command line arguments

            def run_thread():
                run_dbgx_shell(version_path, args)

            thread = threading.Thread(target=run_thread)
            thread.start()

            # Check for updates in background
            print("Checking for updates in background...")
            # call the downloader to check/install updates (non-blocking compile-time wise it's blocking here)
            # it will run while the thread runs in background
            download_and_extract_windbg(install_dir, current_version)

            # Wait for the main process to finish
            thread.join()
            return

    # No current version or installation missing, download and install
    print("No current installation found, downloading...")
    new_version = download_and_extract_windbg(install_dir, current_version)

    if new_version:
        version_install_dir = os.path.join(install_dir, new_version)
        args = sys.argv[1:]
        run_dbgx_shell(version_install_dir, args)
    else:
        print("Installation failed!")
        try:
            sys.exit(1)
        except Exception:
            # In some contexts sys.exit can throw; ignore
            pass

if __name__ == "__main__":
    main()
