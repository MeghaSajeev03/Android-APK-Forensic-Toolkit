import os
import re
import time
import hashlib
import requests
from datetime import datetime

from androguard.core.bytecodes.apk import APK
from androguard.core.analysis.analysis import Analysis

from fpdf import FPDF

API_KEY = "" #enter your apikey

class Analyzer:
    """Static analysis helpers reused by single and dataset modules."""
    URL_PATTERN = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )

    @staticmethod
    def analyze_apk_basic(apk_path):
        try:
            apk = APK(apk_path)
            return {
                "apk_path": apk_path,
                "package_name": apk.get_package(),
                "app_name": apk.get_app_name(),
                "version_code": apk.get_androidversion_code(),
                "version_name": apk.get_androidversion_name(),
                "min_sdk": apk.get_min_sdk_version(),
                "target_sdk": apk.get_target_sdk_version(),
                "permissions": apk.get_permissions(),
                "activities": apk.get_activities(),
                "services": apk.get_services(),
                "receivers": apk.get_receivers(),
                "providers": apk.get_providers(),
                "file_size": os.path.getsize(apk_path)
            }
        except Exception as e:
            return {"basic_analysis_error": f"Error in basic analysis: {e}", "apk_path": apk_path}

    @staticmethod
    def analyze_apk_advanced(apk_path):
        try:
            apk = APK(apk_path)
            dx = Analysis(apk)

            # Certificate analysis
            certificates = apk.get_certificates()
            cert_info = []
            for cert in certificates:
                cert_info.append({
                    "issuer": cert.issuer.rfc4514_string(),
                    "subject": cert.subject.rfc4514_string(),
                    "serial_number": str(cert.serial_number),
                    "not_before": cert.not_valid_before.isoformat(),
                    "not_after": cert.not_valid_after.isoformat()
                })

            # URL extraction from strings
            urls = []
            for s in dx.get_strings():
                try:
                    val = s.get_value()
                    if not val:
                        continue
                    found = Analyzer.URL_PATTERN.findall(val)
                    if found:
                        urls.extend(found)
                except Exception:
                    continue

            return {
                "certificates": cert_info,
                "urls_found": list(dict.fromkeys(urls))[:200],  # unique preserve order, plenty of limit
                "total_urls": len(set(urls)),
                "is_signed": len(certificates) > 0,
                "is_debuggable": apk.is_debuggable()
            }
        except Exception as e:
            return {"advanced_analysis_error": f"Error in advanced analysis: {e}", "apk_path": apk_path}

    @staticmethod
    def analyze_security(apk_path):
        try:
            apk = APK(apk_path)
            permissions = apk.get_permissions()

            dangerous_perms = [
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_CALL_LOG",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.CALL_PHONE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.DEVICE_ADMIN"
            ]
            found_dangerous = [perm for perm in permissions if perm in dangerous_perms]

            uses_internet = "android.permission.INTERNET" in permissions
            uses_network_state = "android.permission.ACCESS_NETWORK_STATE" in permissions

            suspicious_indicators = []
            if "android.permission.RECEIVE_BOOT_COMPLETED" in permissions:
                suspicious_indicators.append("Auto-start on boot")
            if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
                suspicious_indicators.append("Can display over other apps")
            if "android.permission.DEVICE_ADMIN" in permissions:
                suspicious_indicators.append("Device administrator privileges")
            if len(found_dangerous) > 5:
                suspicious_indicators.append("Excessive dangerous permissions")

            return {
                "dangerous_permissions": found_dangerous,
                "dangerous_perm_count": len(found_dangerous),
                "uses_internet": uses_internet,
                "uses_network_state": uses_network_state,
                "suspicious_indicators": suspicious_indicators,
                "total_permissions": len(permissions)
            }
        except Exception as e:
            return {"security_analysis_error": f"Error in security analysis: {e}", "apk_path": apk_path}

    @staticmethod
    def virustotal_scan(apk_path, api_key=API_KEY, timeout=30):
        try:
            with open(apk_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers, timeout=timeout)

            if response.status_code == 200:
                json_data = response.json()
                stats = json_data["data"]["attributes"]["last_analysis_stats"]
                total_scans = sum(stats.values())
                malicious_count = stats.get('malicious', 0)
                return {
                    "vt_malicious": malicious_count,
                    "vt_total": total_scans,
                    "vt_detection_ratio": f"{malicious_count}/{total_scans}" if total_scans else "0/0",
                    "vt_file_hash": file_hash,
                    "vt_scan_date": json_data["data"]["attributes"].get("last_analysis_date", "Unknown")
                }
            else:
                return {
                    "vt_error": f"VirusTotal scan failed. Status: {response.status_code}",
                    "vt_malicious": 0,
                    "vt_total": 0,
                    "vt_file_hash": file_hash
                }
        except Exception as e:
            return {"vt_error": f"VirusTotal scan error: {e}", "vt_malicious": 0, "vt_total": 0}

    @staticmethod
    def calculate_risk_rating(basic, advanced, security, vt):
        try:
            risk_score = 0
            risk_factors = []

            # VirusTotal (0-40)
            vt_malicious = vt.get('vt_malicious', 0)
            vt_total = vt.get('vt_total', 1)
            if vt_total > 0:
                vt_ratio = vt_malicious / vt_total
                if vt_ratio > 0.1:
                    risk_score += 40
                    risk_factors.append("High VirusTotal detection rate")
                elif vt_ratio > 0.05:
                    risk_score += 20
                    risk_factors.append("Moderate VirusTotal detection rate")
                elif vt_ratio > 0:
                    risk_score += 10
                    risk_factors.append("Low VirusTotal detection rate")

            # Dangerous permissions (0-25)
            dangerous_count = security.get('dangerous_perm_count', 0)
            if dangerous_count > 8:
                risk_score += 25
                risk_factors.append("Excessive dangerous permissions")
            elif dangerous_count > 5:
                risk_score += 15
                risk_factors.append("Many dangerous permissions")
            elif dangerous_count > 3:
                risk_score += 10
                risk_factors.append("Several dangerous permissions")

            # Suspicious indicators (0-20)
            suspicious = security.get('suspicious_indicators', [])
            risk_score += min(len(suspicious) * 5, 20)
            if suspicious:
                risk_factors.extend(suspicious)

            # Certificate issues (0-15)
            certificates = advanced.get('certificates', [])
            if not certificates:
                risk_score += 15
                risk_factors.append("No valid certificates found")
            elif advanced.get('is_debuggable', False):
                risk_score += 10
                risk_factors.append("Debug mode enabled")

            # Determine risk level
            if risk_score >= 60:
                risk_level = "HIGH RISK"
                is_malicious = "LIKELY MALICIOUS"
                color = "red"
            elif risk_score >= 35:
                risk_level = "MEDIUM RISK"
                is_malicious = "POTENTIALLY SUSPICIOUS"
                color = "orange"
            elif risk_score >= 15:
                risk_level = "LOW RISK"
                is_malicious = "LIKELY SAFE"
                color = "yellow"
            else:
                risk_level = "MINIMAL RISK"
                is_malicious = "SAFE"
                color = "green"

            return {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "is_malicious": is_malicious,
                "risk_color": color,
                "risk_factors": risk_factors,
                "analysis_date": datetime.now().isoformat()
            }
        except Exception as e:
            return {"risk_calculation_error": f"Error calculating risk: {e}"}

    @staticmethod
    def sanitize_text(text):
        if not text:
            return "Unknown"
        replacements = {
            '\u2022': '-',
            '\u2013': '-',
            '\u2014': '--',
            '\u2018': "'",
            '\u2019': "'",
            '\u201c': '"',
            '\u201d': '"',
            '\u2026': '...'
        }
        for u, a in replacements.items():
            text = text.replace(u, a)
        try:
            return str(text).encode('latin-1', errors='replace').decode('latin-1')
        except:
            return ''.join(char for char in str(text) if ord(char) < 128)

def generate_single_pdf(result, output_dir=None):
    """Generate a single APK report PDF using fpdf. Returns path to saved PDF."""
    try:
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Arial", "B", 20)
        pdf.cell(0, 15, "APK Forensic Analysis Report", ln=True, align='C')
        pdf.ln(5)

        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        pdf.ln(10)

        pdf.set_font("Arial", "B", 16)
        pdf.set_fill_color(200, 220, 255)
        pdf.cell(0, 10, "SECURITY ASSESSMENT", ln=True, fill=True)
        pdf.ln(5)

        pdf.set_font("Arial", "B", 14)
        risk_level = Analyzer.sanitize_text(result.get('risk_level', 'Unknown'))
        is_malicious = Analyzer.sanitize_text(result.get('is_malicious', 'Unknown'))
        risk_score = result.get('risk_score', 0)

        pdf.cell(0, 8, f"Risk Level: {risk_level}", ln=True)
        pdf.cell(0, 8, f"Classification: {is_malicious}", ln=True)
        pdf.cell(0, 8, f"Risk Score: {risk_score}/100", ln=True)
        pdf.ln(5)

        pdf.set_font("Arial", "B", 14)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(0, 8, "APPLICATION INFORMATION", ln=True, fill=True)
        pdf.set_font("Arial", "", 12)

        basic_info = [
            ("Package Name", Analyzer.sanitize_text(result.get('package_name', 'Unknown'))),
            ("App Name", Analyzer.sanitize_text(result.get('app_name', 'Unknown'))),
            ("Version", f"{Analyzer.sanitize_text(result.get('version_name', 'Unknown'))} ({result.get('version_code', 'Unknown')})"),
            ("File Size", f"{result.get('file_size', 0) / (1024*1024):.2f} MB"),
            ("Min SDK", str(result.get('min_sdk', 'Unknown'))),
            ("Target SDK", str(result.get('target_sdk', 'Unknown'))),
            ("Signed", "Yes" if result.get('is_signed', False) else "No"),
            ("Debuggable", "Yes" if result.get('is_debuggable', False) else "No")
        ]
        for label, value in basic_info:
            pdf.cell(0, 6, f"{label}: {Analyzer.sanitize_text(str(value))}", ln=True)
        pdf.ln(5)

        # Security analysis short
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 8, "SECURITY ANALYSIS", ln=True, fill=True)
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 6, f"Total Permissions: {result.get('total_permissions', 0)}", ln=True)
        pdf.cell(0, 6, f"Dangerous Permissions: {result.get('dangerous_perm_count', 0)}", ln=True)
        pdf.cell(0, 6, f"Internet Access: {'Yes' if result.get('uses_internet', False) else 'No'}", ln=True)
        pdf.cell(0, 6, f"URLs Found: {result.get('total_urls', 0)}", ln=True)
        pdf.ln(3)

        # VirusTotal
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 6, "VirusTotal Scan Results:", ln=True)
        pdf.set_font("Arial", "", 12)
        vt_ratio = Analyzer.sanitize_text(str(result.get('vt_detection_ratio', 'N/A')))
        vt_hash = Analyzer.sanitize_text(str(result.get('vt_file_hash', 'N/A')))
        pdf.cell(0, 6, f"Detection Ratio: {vt_ratio}", ln=True)
        pdf.cell(0, 6, f"File Hash: {vt_hash}", ln=True)
        pdf.ln(5)

        # Summary & recommendations
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 8, "ANALYSIS SUMMARY", ln=True, fill=True)
        pdf.set_font("Arial", "", 12)
        if risk_score >= 60:
            recommendation = "HIGH RISK - This APK shows multiple indicators of malicious behavior. Recommend blocking or quarantining."
        elif risk_score >= 35:
            recommendation = "MEDIUM RISK - This APK has suspicious characteristics. Review and monitor usage carefully."
        elif risk_score >= 15:
            recommendation = "LOW RISK - This APK has some minor security concerns but appears generally safe."
        else:
            recommendation = "MINIMAL RISK - This APK appears to be safe based on current analysis."

        pdf.multi_cell(0, 6, Analyzer.sanitize_text(recommendation))

        # Footer
        pdf.ln(5)
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 5, "Report generated by Android APK Forensics Toolkit", ln=True, align='C')
        pdf.cell(0, 5, f"Analysis completed on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}", ln=True, align='C')

        # Save PDF
        filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, filename)
        else:
            output_path = os.path.join(os.getcwd(), filename)
        pdf.output(output_path)
        return output_path
    except Exception as e:
        raise RuntimeError(f"PDF generation failed: {e}")
