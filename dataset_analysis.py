import os
import time
from datetime import datetime
from typing import List, Dict, Optional
from fpdf import FPDF

try:
    from single_analysis import Analyzer, API_KEY
except Exception:
    class Analyzer:
        @staticmethod
        def analyze_apk_basic(apk_path): return {"apk_path": apk_path, "app_name": os.path.basename(apk_path)}
        @staticmethod
        def analyze_apk_advanced(apk_path): return {"total_urls": 0, "urls_found": [], "certificates": [], "is_debuggable": False, "is_signed": False}
        @staticmethod
        def analyze_security(apk_path): return {"dangerous_permissions": [], "dangerous_perm_count": 0}
        @staticmethod
        def virustotal_scan(apk_path, api_key="" , timeout=15): return {"vt_malicious": 0, "vt_total": 0, "vt_detection_ratio": "0/0", "vt_file_hash": "N/A"}
        @staticmethod
        def calculate_risk_rating(basic, advanced, security, vt): 
            return {"risk_score": 0, "risk_level": "MINIMAL RISK", "is_malicious": "SAFE", "risk_color": "green", "risk_factors": []}
    API_KEY = "" 

try:
    from PyQt5.QtCore import QThread, pyqtSignal
    _PYQT_AVAILABLE = True
except Exception:
    QThread = object
    def pyqtSignal(*a, **k): return None
    _PYQT_AVAILABLE = False

def safe_unicode(text):
    """Ensure all characters are printable."""
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    try:
        text.encode("latin-1")
        return text
    except UnicodeEncodeError:
        replacements = {
            '\u043a': 'k', '\u0438': 'i', '\u0440': 'r', '\u043f': 'p',
            '\u043b': 'l', '\u0441': 's', '\u0432': 'v', '\u0443': 'u',
            '\u0430': 'a', '\u0435': 'e', '\u043d': 'n', '\u043e': 'o'
        }
        for k, v in replacements.items():
            text = text.replace(k, v)
        return text.encode('ascii', errors='replace').decode('ascii')

class StyledPDF(FPDF):
    """Clean forensic-style PDF with all font styles and Unicode."""

    def __init__(self, title="Android APK Forensics Toolkit - Dataset Report"):
        super().__init__('P', 'mm', 'A4')
        self.title = title
        self.set_auto_page_break(auto=True, margin=20)
        self._add_fonts()

    def _add_fonts(self):
        base_dir = os.path.dirname(__file__)
        font_path = os.path.join(base_dir, "DejaVuSans.ttf")
        try:
            if not os.path.exists(font_path):
                raise FileNotFoundError("DejaVuSans.ttf not found in module directory.")
            # Register all style variants
            self.add_font("DejaVu", "", font_path, uni=True)
            self.add_font("DejaVu", "B", font_path, uni=True)
            self.add_font("DejaVu", "I", font_path, uni=True)
            self.add_font("DejaVu", "BI", font_path, uni=True)
            self.default_font = "DejaVu"
        except Exception:
            self.default_font = "Arial"

    def header(self):
        if getattr(self, "_on_cover", False):
            return
        self.set_font(self.default_font, "B", 12)
        self.set_text_color(50, 50, 50)
        self.cell(0, 8, self.title, align="C", ln=True)
        self.set_draw_color(180, 180, 180)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font(self.default_font, "I", 9)
        self.set_text_color(130, 130, 130)
        self.cell(0, 6, f"Page {self.page_no()}", align="C")

def _cover_page(pdf: StyledPDF, summary: Dict):
    pdf.add_page()
    pdf._on_cover = True
    pdf.set_font(pdf.default_font, "B", 22)
    pdf.set_text_color(20, 30, 60)
    pdf.ln(25)
    pdf.cell(0, 12, "Android APK Forensics Toolkit", ln=True, align="C")
    pdf.set_font(pdf.default_font, "", 14)
    pdf.cell(0, 10, "Dataset Analysis Report", ln=True, align="C")
    pdf.ln(15)
    pdf.set_font(pdf.default_font, "", 11)
    left = 35
    info = [
        ("Generated On", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Total APKs", summary.get("apk_count", 0)),
        ("Average Risk Score", summary.get("avg_risk_score", 0))
    ]
    for k, v in info:
        pdf.set_x(left)
        pdf.cell(40, 8, f"{k}:", border=0)
        pdf.set_x(left + 45)
        pdf.cell(100, 8, safe_unicode(v), ln=True)
    pdf.ln(10)
    pdf.set_font(pdf.default_font, "I", 10)
    pdf.set_text_color(90, 90, 90)
    pdf.multi_cell(0, 6,
        "This forensic report contains dataset-level APK analysis results. "
        "Each entry represents an APK file analyzed for permissions, VirusTotal data, "
        "and risk classification for investigative review."
    )
    pdf._on_cover = False


def _summary_page(pdf: StyledPDF, summary: Dict):
    pdf.add_page()
    pdf.set_font(pdf.default_font, "B", 16)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, "Dataset Summary", ln=True)
    pdf.ln(4)
    pdf.set_fill_color(245, 245, 245)
    pdf.set_draw_color(200, 200, 200)
    y = pdf.get_y()
    pdf.rect(12, y, 186, 32, style='F')
    pdf.set_xy(16, y + 3)
    pdf.set_font(pdf.default_font, "", 11)
    pdf.cell(0, 6, f"APKs analyzed: {summary.get('apk_count', 0)}", ln=True)
    pdf.cell(0, 6, f"Average risk score: {summary.get('avg_risk_score', 0)}", ln=True)
    pdf.cell(0, 6,
        f"Risk levels (H/M/L/Mn): "
        f"{summary.get('high_count',0)}/{summary.get('medium_count',0)}/"
        f"{summary.get('low_count',0)}/{summary.get('minimal_count',0)}", ln=True)
    pdf.cell(0, 6, f"Total VT malicious detections: {summary.get('total_vt_malicious_detections',0)}", ln=True)
    pdf.ln(12)


def _apk_card(pdf: StyledPDF, idx: int, r: Dict):
    """Auto-aligned, non-overlapping APK summary card."""
    pdf.set_font(pdf.default_font, "B", 12)
    pdf.set_text_color(20, 40, 90)
    pdf.multi_cell(0, 8, safe_unicode(f"{idx}. {r.get('app_name','Unknown')}"))
    pdf.ln(1)

    pdf.set_font(pdf.default_font, "", 10)
    pdf.set_text_color(40, 40, 40)
    lines = [
        f"Package: {r.get('package_name','Unknown')}",
        f"Risk: {r.get('risk_level','Unknown')} (Score: {r.get('risk_score',0)})",
        f"VirusTotal: {r.get('vt_detection_ratio','N/A')}",
        f"Total URLs: {r.get('total_urls',0)}"
    ]
    for line in lines:
        pdf.multi_cell(0, 6, safe_unicode(line))

    dp = r.get('dangerous_permissions', [])
    dp_preview = ", ".join(dp[:6]) + ("..." if len(dp) > 6 else "")
    pdf.multi_cell(0, 6, safe_unicode(f"Dangerous Permissions: {dp_preview}"))

    rf = r.get('risk_factors', [])
    if rf:
        rf_text = "; ".join(rf[:4]) + ("..." if len(rf) > 4 else "")
        pdf.set_font(pdf.default_font, "I", 9)
        pdf.multi_cell(0, 5, safe_unicode(f"Risk Factors: {rf_text}"))

    pdf.ln(4)
    pdf.set_draw_color(220, 220, 220)
    pdf.line(12, pdf.get_y(), 198, pdf.get_y())
    pdf.ln(6)


# =========================================================
# PDF Generator
# =========================================================
def generate_dataset_pdf(results: List[Dict], summary: Dict, output_dir: Optional[str] = None) -> str:
    """Generates clean, aligned, Unicode-safe forensic dataset report."""
    try:
        pdf = StyledPDF()
        pdf.set_font(pdf.default_font, "", 11)

        _cover_page(pdf, summary)
        _summary_page(pdf, summary)

        for i, r in enumerate(results, start=1):
            if i == 1 or pdf.get_y() > 250:
                pdf.add_page()
            _apk_card(pdf, i, r)

        pdf.add_page()
        pdf.set_font(pdf.default_font, "B", 14)
        pdf.cell(0, 10, "Final Notes", ln=True)
        pdf.set_font(pdf.default_font, "", 11)
        pdf.multi_cell(0, 6,
            "This report was automatically generated by the Android APK Forensics Toolkit. "
            "Each APK entry includes static and VirusTotal findings for forensic validation."
        )
        pdf.ln(6)
        pdf.set_font(pdf.default_font, "I", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 6, f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")

        filename = f"dataset_forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            path = os.path.join(output_dir, filename)
        else:
            path = os.path.join(os.getcwd(), filename)
        pdf.output(path)
        return path
    except Exception as e:
        raise RuntimeError(f"Dataset PDF generation failed: {e}")

def analyze_dataset_folder(folder: str, api_key: Optional[str] = "" , progress_cb: Optional[callable] = None) -> Dict:
    results = []
    apks = [os.path.join(folder, f) for f in os.listdir(folder) if f.lower().endswith(".apk")]
    total = len(apks)
    if total == 0:
        return {"results": [], "summary": {"apk_count": 0}}

    for idx, apk_path in enumerate(apks, start=1):
        try:
            if progress_cb:
                progress_cb(int((idx - 1) / total * 100), f"Analyzing {os.path.basename(apk_path)}")
            basic = Analyzer.analyze_apk_basic(apk_path)
            advanced = Analyzer.analyze_apk_advanced(apk_path)
            security = Analyzer.analyze_security(apk_path)
            vt = Analyzer.virustotal_scan(apk_path, api_key or API_KEY)
            risk = Analyzer.calculate_risk_rating(basic, advanced, security, vt)
            results.append({**basic, **advanced, **security, **vt, **risk})
            if progress_cb:
                progress_cb(int(idx / total * 100), f"Completed {os.path.basename(apk_path)}")
            time.sleep(0.05)
        except Exception as e:
            results.append({"apk_path": apk_path, "error": str(e)})

    total_vt = sum(r.get('vt_malicious', 0) for r in results)
    avg_risk = round(sum(r.get('risk_score', 0) for r in results) / max(1, total), 2)
    counts = {
        "high_count": sum(1 for r in results if "HIGH" in r.get('risk_level', '')),
        "medium_count": sum(1 for r in results if "MEDIUM" in r.get('risk_level', '')),
        "low_count": sum(1 for r in results if "LOW" in r.get('risk_level', '')),
        "minimal_count": sum(1 for r in results if "MINIMAL" in r.get('risk_level', ''))
    }
    summary = {
        "apk_count": total,
        "avg_risk_score": avg_risk,
        "total_vt_malicious_detections": total_vt,
        **counts
    }
    return {"results": results, "summary": summary}


if _PYQT_AVAILABLE:
    class DatasetAnalysisThread(QThread):
        progress_updated = pyqtSignal(int, str)
        dataset_completed = pyqtSignal(dict)

        def __init__(self, folder, api_key="" , parent=None):
            super().__init__(parent)
            self.folder = folder
            self.api_key = api_key or API_KEY

        def run(self):
            try:
                def cb(p, msg):
                    self.progress_updated.emit(int(p), msg)
                payload = analyze_dataset_folder(self.folder, api_key=self.api_key, progress_cb=cb)
                self.dataset_completed.emit(payload)
            except Exception as e:
                self.dataset_completed.emit({"error": str(e)})

if __name__ == "__main__":
    test_dir = os.getcwd()
    print("[+] Running dataset test on:", test_dir)
    data = analyze_dataset_folder(test_dir)
    out = generate_dataset_pdf(data["results"], data["summary"])
    print("PDF saved at:", out)
