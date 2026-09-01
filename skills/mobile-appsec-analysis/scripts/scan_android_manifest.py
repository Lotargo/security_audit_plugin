#!/usr/bin/env python3
import sys
import xml.etree.ElementTree as ET

def scan_manifest(manifest_path):
    findings = []
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        app = root.find('application')
        if app is not None:
            if app.attrib.get('{http://schemas.android.com/apk/res/android}debuggable') == 'true':
                findings.append("HIGH: android:debuggable='true' enabled in manifest")
            if app.attrib.get('{http://schemas.android.com/apk/res/android}allowBackup') == 'true':
                findings.append("MEDIUM: android:allowBackup='true' enabled without scoped backup rules")
            if app.attrib.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic') == 'true':
                findings.append("HIGH: android:usesCleartextTraffic='true' allows unencrypted HTTP")

            for comp in app.findall('activity') + app.findall('service') + app.findall('receiver') + app.findall('provider'):
                if comp.attrib.get('{http://schemas.android.com/apk/res/android}exported') == 'true':
                    perm = comp.attrib.get('{http://schemas.android.com/apk/res/android}permission')
                    name = comp.attrib.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                    if not perm:
                        findings.append(f"HIGH: Exported component without permission: {name}")
    except Exception as e:
        findings.append(f"Error parsing manifest: {str(e)}")
    return findings

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "AndroidManifest.xml"
    import json
    print(json.dumps({"manifest": target, "findings": scan_manifest(target)}, indent=2))
