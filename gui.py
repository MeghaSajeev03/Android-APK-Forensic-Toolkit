import os
import sys
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QFileDialog, QTextEdit,
    QVBoxLayout, QWidget, QMessageBox, QLabel, QHBoxLayout, QStatusBar,
    QProgressBar, QScrollArea, QFrame, QGridLayout
)
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor
from PyQt5.QtCore import Qt

from single_analysis import Analyzer, generate_single_pdf, API_KEY
from single_analysis import Analyzer as _Analyzer  # alias for local usage
from single_analysis import generate_single_pdf as _generate_single_pdf
from single_analysis import API_KEY as VT_API_KEY

from single_analysis import Analyzer
from single_analysis import generate_single_pdf
from dataset_analysis import DatasetAnalysisThread, generate_dataset_pdf

# We also need a small QThread wrapper for single APK to keep GUI responsive.
from PyQt5.QtCore import QThread, pyqtSignal

class SingleAnalysisThread(QThread):
    progress_updated = pyqtSignal(int, str)
    analysis_completed = pyqtSignal(dict)

    def __init__(self, apk_path, api_key=VT_API_KEY):
        super().__init__()
        self.apk_path = apk_path
        self.api_key = api_key

    def run(self):
        try:
            # Light staged updates to show progress
            self.progress_updated.emit(5, "Loading APK...")
            time.sleep(0.2)
            basic = Analyzer.analyze_apk_basic(self.apk_path)
            self.progress_updated.emit(25, "Basic analysis done.")
            time.sleep(0.15)
            advanced = Analyzer.analyze_apk_advanced(self.apk_path)
            self.progress_updated.emit(50, "Advanced analysis done.")
            time.sleep(0.15)
            security = Analyzer.analyze_security(self.apk_path)
            self.progress_updated.emit(70, "Security analysis done.")
            time.sleep(0.15)
            vt = Analyzer.virustotal_scan(self.apk_path, self.api_key)
            self.progress_updated.emit(90, "VirusTotal check done.")
            time.sleep(0.1)
            risk = Analyzer.calculate_risk_rating(basic, advanced, security, vt)
            result = {**basic, **advanced, **security, **vt, **risk}
            self.progress_updated.emit(100, "Analysis complete.")
            self.analysis_completed.emit(result)
        except Exception as e:
            self.analysis_completed.emit({"error": str(e)})

class APKAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Android APK Forensics Toolkit")
        self.setGeometry(100, 100, 1000, 700)
        # self.setWindowIcon(QIcon("icon.png"))  # optional icon
        self.result = None
        self.dataset_results = None
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()

        # Title
        title_label = QLabel("Android APK Forensics Toolkit")
        title_label.setFont(QFont("Arial", 20, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("""
            color: #2c3e50;
            padding: 15px;
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #3498db, stop:1 #2980b9);
            color: white;
            border-radius: 10px;
            margin-bottom: 10px;
        """)

        # Button layout
        button_layout = QHBoxLayout()

        self.load_button = QPushButton("📁 Load APK")
        self.load_button.clicked.connect(self.load_apk)

        self.load_dataset_button = QPushButton("📂 Load Dataset (Folder)")
        self.load_dataset_button.clicked.connect(self.load_dataset)

        self.analyze_button = QPushButton("🔍 Analyze APK")
        self.analyze_button.clicked.connect(self.analyze_apk)
        self.analyze_button.setEnabled(False)

        self.analyze_dataset_button = QPushButton("🔎 Analyze Dataset")
        self.analyze_dataset_button.clicked.connect(self.analyze_dataset)
        self.analyze_dataset_button.setEnabled(False)

        self.report_button = QPushButton("📄 Generate Single Report")
        self.report_button.clicked.connect(self.generate_pdf_single)
        self.report_button.setEnabled(False)

        self.dataset_report_button = QPushButton("📊 Generate Dataset Report")
        self.dataset_report_button.clicked.connect(self.generate_pdf_dataset)
        self.dataset_report_button.setEnabled(False)

        self.exit_button = QPushButton("❌ Exit")
        self.exit_button.clicked.connect(self.close)

        for btn in [self.load_button, self.load_dataset_button, self.analyze_button,
                    self.analyze_dataset_button, self.report_button, self.dataset_report_button,
                    self.exit_button]:
            btn.setStyleSheet("""
                QPushButton {
                    padding: 10px 14px;
                    font-size: 13px;
                    font-weight: bold;
                    border-radius: 8px;
                    background-color: #34495e;
                    color: white;
                    border: none;
                }
                QPushButton:hover {
                    background-color: #2c3e50;
                }
                QPushButton:disabled {
                    background-color: #95a5a6;
                }
            """)
            button_layout.addWidget(btn)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_label = QLabel("")
        self.progress_label.setAlignment(Qt.AlignCenter)
        self.progress_label.setVisible(False)

        # Results area
        self.results_scroll = QScrollArea()
        self.results_widget = QWidget()
        self.results_layout = QVBoxLayout(self.results_widget)
        self.results_scroll.setWidget(self.results_widget)
        self.results_scroll.setWidgetResizable(True)
        self.results_scroll.setStyleSheet("""
            QScrollArea {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                background-color: #ecf0f1;
            }
        """)

        main_layout.addWidget(title_label)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.progress_label)
        main_layout.addWidget(self.results_scroll)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Ready - Load an APK file or dataset folder to begin analysis")

    def load_apk(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select APK File", "", "APK Files (*.apk)"
        )
        if file_path:
            self.apk_path = file_path
            self.analyze_button.setEnabled(True)
            filename = os.path.basename(file_path)
            self.status.showMessage(f"Loaded: {filename}")
            self.clear_results()

            file_size = os.path.getsize(file_path) / (1024 * 1024)
            info_label = QLabel(f"📱 Loaded APK: {filename}\n📏 Size: {file_size:.2f} MB")
            info_label.setStyleSheet("""
                background-color: #d5dbdb;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            """)
            self.results_layout.addWidget(info_label)

    def load_dataset(self):
        folder = QFileDialog.getExistingDirectory(self, "Select APK Folder", "")
        if folder:
            self.dataset_folder = folder
            self.analyze_dataset_button.setEnabled(True)
            filename = os.path.basename(folder)
            self.status.showMessage(f"Loaded dataset folder: {filename}")
            self.clear_results()
            info_label = QLabel(f"📂 Loaded dataset folder: {folder}")
            info_label.setStyleSheet("""
                background-color: #d5dbdb;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            """)
            self.results_layout.addWidget(info_label)

    def analyze_apk(self):
        if not hasattr(self, "apk_path"):
            QMessageBox.warning(self, "Warning", "Please load an APK file first.")
            return
        self.progress_bar.setVisible(True)
        self.progress_label.setVisible(True)
        self.analyze_button.setEnabled(False)
        self.clear_results()

        self.single_thread = SingleAnalysisThread(self.apk_path, API_KEY)
        self.single_thread.progress_updated.connect(self.update_progress)
        self.single_thread.analysis_completed.connect(self.on_single_analysis_complete)
        self.single_thread.start()

    def analyze_dataset(self):
        if not hasattr(self, "dataset_folder"):
            QMessageBox.warning(self, "Warning", "Please load a dataset folder first.")
            return
        self.progress_bar.setVisible(True)
        self.progress_label.setVisible(True)
        self.analyze_dataset_button.setEnabled(False)
        self.clear_results()

        self.dataset_thread = DatasetAnalysisThread(self.dataset_folder, API_KEY)
        self.dataset_thread.progress_updated.connect(self.update_progress)
        self.dataset_thread.dataset_completed.connect(self.on_dataset_complete)
        self.dataset_thread.start()

    def update_progress(self, value, message):
        # Keep progress UI responsive
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
        self.status.showMessage(message)

    def on_single_analysis_complete(self, result):
        self.result = result
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.analyze_button.setEnabled(True)
        self.report_button.setEnabled(True)

        if "error" in result:
            QMessageBox.critical(self, "Analysis Error", result["error"])
            return

        self.display_analysis_summary(result)
        self.status.showMessage("Analysis complete - Ready to generate report")

    def on_dataset_complete(self, payload):
        if "error" in payload:
            QMessageBox.critical(self, "Dataset Error", payload["error"])
            self.progress_bar.setVisible(False)
            self.progress_label.setVisible(False)
            self.analyze_dataset_button.setEnabled(True)
            return

        self.dataset_results = payload
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.analyze_dataset_button.setEnabled(True)
        self.dataset_report_button.setEnabled(True)
        self.status.showMessage("Dataset analysis complete - Ready to generate dataset report")

        # display summary
        self.clear_results()
        summary = payload.get("summary", {})
        items = [
            f"APKs analyzed: {summary.get('apk_count',0)}",
            f"Average risk score: {summary.get('avg_risk_score',0)}",
            f"High/Med/Low/Minimal: {summary.get('high_count',0)}/{summary.get('medium_count',0)}/{summary.get('low_count',0)}/{summary.get('minimal_count',0)}",
            f"Total VT malicious detections (sum): {summary.get('total_vt_malicious_detections',0)}"
        ]
        frame = self.create_info_frame("📊 DATASET SUMMARY", items)
        self.results_layout.addWidget(frame)

        # Show short top 5 APKs by risk score
        results = payload.get("results", [])
        sorted_by_risk = sorted(results, key=lambda x: x.get('risk_score',0), reverse=True)
        top5 = sorted_by_risk[:5]
        details = []
        for r in top5:
            details.append(f"{r.get('app_name','Unknown')} — {r.get('risk_level','?')} ({r.get('risk_score',0)})")
        if details:
            self.results_layout.addWidget(self.create_info_frame("Top 5 by risk", details))

    def display_analysis_summary(self, result):
        self.clear_results()

        # Risk Assessment Card
        risk_level = result.get('risk_level', 'Unknown')
        is_malicious = result.get('is_malicious', 'Unknown')
        risk_score = result.get('risk_score', 0)
        risk_color = result.get('risk_color', 'gray')

        risk_frame = QFrame()
        risk_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {self.get_risk_bg_color(risk_color)};
                border: 3px solid {risk_color};
                border-radius: 10px;
                padding: 15px;
                margin: 10px;
            }}
        """)
        risk_layout = QVBoxLayout(risk_frame)
        risk_title = QLabel("🛡️ SECURITY ASSESSMENT")
        risk_title.setFont(QFont("Arial", 16, QFont.Bold))
        risk_title.setAlignment(Qt.AlignCenter)
        risk_level_label = QLabel(f"Risk Level: {risk_level}")
        risk_level_label.setFont(QFont("Arial", 14, QFont.Bold))
        malicious_label = QLabel(f"Status: {is_malicious}")
        malicious_label.setFont(QFont("Arial", 14, QFont.Bold))
        score_label = QLabel(f"Risk Score: {risk_score}/100")
        score_label.setFont(QFont("Arial", 12))
        risk_layout.addWidget(risk_title)
        risk_layout.addWidget(risk_level_label)
        risk_layout.addWidget(malicious_label)
        risk_layout.addWidget(score_label)
        self.results_layout.addWidget(risk_frame)

        findings_frame = self.create_info_frame("🔍 KEY FINDINGS", [
            f"Package: {result.get('package_name', 'Unknown')}",
            f"App Name: {result.get('app_name', 'Unknown')}",
            f"Version: {result.get('version_name', 'Unknown')}",
            f"Dangerous Permissions: {result.get('dangerous_perm_count', 0)}",
            f"VirusTotal Detection: {result.get('vt_detection_ratio', 'N/A')}",
            f"URLs Found: {result.get('total_urls', 0)}",
            f"Signed: {'Yes' if result.get('is_signed', False) else 'No'}"
        ])
        self.results_layout.addWidget(findings_frame)

        if result.get('risk_factors'):
            risk_factors_frame = self.create_info_frame("⚠️ RISK FACTORS", result['risk_factors'])
            self.results_layout.addWidget(risk_factors_frame)

    def create_info_frame(self, title, items):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 8px;
                padding: 10px;
                margin: 5px;
            }
        """)
        layout = QVBoxLayout(frame)
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setStyleSheet("color: #495057; margin-bottom: 10px;")
        layout.addWidget(title_label)
        for item in items:
            item_label = QLabel(f"• {item}")
            item_label.setFont(QFont("Arial", 11))
            item_label.setWordWrap(True)
            layout.addWidget(item_label)
        return frame

    def get_risk_bg_color(self, color):
        color_map = {
            'red': '#ffebee',
            'orange': '#fff3e0',
            'yellow': '#fffde7',
            'green': '#e8f5e8'
        }
        return color_map.get(color, '#f5f5f5')

    def clear_results(self):
        for i in reversed(range(self.results_layout.count())):
            child = self.results_layout.itemAt(i).widget()
            if child:
                child.setParent(None)

    def sanitize_text(self, text):
        return Analyzer.sanitize_text(text)

    def generate_pdf_single(self):
        if not getattr(self, "result", None):
            QMessageBox.warning(self, "Warning", "Analyze an APK before generating report.")
            return
        try:
            output = generate_single_pdf(self.result)
            QMessageBox.information(self, "PDF Report", f"Detailed forensic report saved as:\n{output}")
            self.status.showMessage(f"Report generated: {output}")
        except Exception as e:
            QMessageBox.critical(self, "PDF Generation Error", str(e))

    def generate_pdf_dataset(self):
        if not getattr(self, "dataset_results", None):
            QMessageBox.warning(self, "Warning", "Analyze a dataset before generating report.")
            return
        try:
            results = self.dataset_results.get("results", [])
            summary = self.dataset_results.get("summary", {})
            output = generate_dataset_pdf(results, summary)
            QMessageBox.information(self, "Dataset PDF Report", f"Combined dataset report saved as:\n{output}")
            self.status.showMessage(f"Dataset report generated: {output}")
        except Exception as e:
            QMessageBox.critical(self, "PDF Generation Error", str(e))
