# Android-APK-Forensic-Toolkit
The Android APK Forensics Toolkit is a comprehensive desktop application designed
to analyze Android application package (APK) files for forensic and security evaluation.
Developed using Python (PyQt5), the toolkit integrates androguard for static analysis and the
VirusTotal API for real-time malware reputation checking. It supports both single APK
analysis and bulk dataset evaluation, allowing forensic investigators and cybersecurity
analysts to assess applications efficiently.
 The toolkit performs multiple layers of analysis—extracting metadata, permissions,
activities, and certificates; identifying embedded URLs; and detecting the use of dangerous
permissions or suspicious behaviors. Each analyzed APK is automatically assigned a risk
score and classification level (Minimal, Low, Medium, or High Risk) using a weighted
scoring model that evaluates permission usage, certificate trust, debuggability, and
VirusTotal detections.
 For investigative documentation, the toolkit can generate detailed forensic PDF
reports—including single-APK reports and combined dataset summaries—using structured
layouts with Unicode-safe text rendering. The application offers a user-friendly graphical
interface with real-time progress feedback, interactive analysis summaries, and automated
report generation, making it suitable for malware analysis labs, digital forensics research,
and Android application vetting.
 This project demonstrates the integration of open-source forensic frameworks with
automated visualization and reporting mechanisms, providing a reliable and extensible
platform for Android application forensics.
