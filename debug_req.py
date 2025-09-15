#!/usr/bin/env python3
"""
Simple test to debug WinDbg download URL parsing
"""

import requests
import xml.etree.ElementTree as ET


def test_windbg_url():
    """Test the WinDbg download URL and see what we get"""
    url = "https://aka.ms/windbg/download"
    
    print(f"Testing URL: {url}")
    
    try:
        print("Making request...")
        resp = requests.get(url, timeout=30)
        print(f"Status code: {resp.status_code}")
        print(f"Final URL: {resp.url}")
        print(f"Content-Type: {resp.headers.get('Content-Type', 'unknown')}")
        print(f"Content-Length: {resp.headers.get('Content-Length', 'unknown')}")
        print(f"Response length: {len(resp.text)} characters")
        
        # Save full response
        with open("debug_full_response.txt", "w", encoding="utf-8") as f:
            f.write(f"Status: {resp.status_code}\n")
            f.write(f"URL: {resp.url}\n")
            f.write(f"Headers: {dict(resp.headers)}\n")
            f.write("=" * 80 + "\n")
            f.write(resp.text)
        
        print("Full response saved to debug_full_response.txt")
        
        # Show preview
        text = resp.text
        print(f"\nFirst 1000 characters of response:")
        print("-" * 80)
        print(text[:1000])
        print("-" * 80)
        
        # Check if it contains AppInstaller
        if "<AppInstaller" in text:
            print("✓ Found '<AppInstaller' in response")
            start_pos = text.find("<AppInstaller")
            print(f"Position: {start_pos}")
            
            # Show context around AppInstaller
            context_start = max(0, start_pos - 100)
            context_end = min(len(text), start_pos + 500)
            print(f"Context around AppInstaller:")
            print(text[context_start:context_end])
            
        else:
            print("✗ '<AppInstaller' NOT found in response")
            # Check for variations
            variations = ["appinstaller", "AppInstaller", "APPINSTALLER"]
            for var in variations:
                if var in text.lower():
                    print(f"Found variation: {var}")
        
        # Try to parse as XML
        print("\nTrying XML parsing...")
        try:
            root = ET.fromstring(text)
            print(f"✓ Successfully parsed as XML")
            print(f"Root tag: {root.tag}")
            print(f"Root attributes: {root.attrib}")
            
            # Show all top-level elements
            print("Top-level elements:")
            for child in root:
                print(f"  {child.tag}: {child.attrib}")
                
        except ET.ParseError as e:
            print(f"✗ XML parsing failed: {e}")
            
            # Try to extract AppInstaller section
            if "<AppInstaller" in text:
                print("Attempting to extract AppInstaller section...")
                start = text.find("<AppInstaller")
                end = text.find("</AppInstaller>", start)
                if end != -1:
                    xml_section = text[start:end + len("</AppInstaller>")]
                    print(f"Extracted section length: {len(xml_section)}")
                    
                    try:
                        section_root = ET.fromstring(xml_section)
                        print(f"✓ Successfully parsed AppInstaller section")
                        print(f"Section root tag: {section_root.tag}")
                        print(f"Section attributes: {section_root.attrib}")
                        
                        # Look for MainBundle/MainPackage
                        for child in section_root:
                            print(f"  Child: {child.tag} - {child.attrib}")
                            
                    except ET.ParseError as e2:
                        print(f"✗ AppInstaller section parsing failed: {e2}")
                        print("AppInstaller section content:")
                        print(xml_section[:500])
                        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False


if __name__ == "__main__":
    test_windbg_url()