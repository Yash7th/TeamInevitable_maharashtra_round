"""All-Python ModelLedger provenance verification frontend.

Run with:
    streamlit run streamlit_app.py
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st


HISTORY_FILE = Path(__file__).parent / "verification_history.json"
MAX_FILE_SIZE = 250 * 1024 * 1024
DETECTORS = {
    "Local forensic checks": "Metadata, file structure, and fingerprint signals",
    "Content detector adapter": "Connect a configured image AI detector",
    "Provenance ledger": "Signed origin and transformation events",
}


def configure_page() -> None:
    st.set_page_config(
        page_title="ModelLedger | Provenance verification",
        page_icon="◈",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(
        """
        <style>
        .block-container { max-width: 1180px; padding-top: 2rem; }
        .report-box { background:#f7f9fc; border:1px solid #dfe6ef; border-radius:8px; padding:1rem; }
        .status { display:inline-block; padding:.35rem .6rem; border-radius:5px; font-size:.78rem; font-weight:700; }
        .status-warning { color:#9a650c; background:#fff3d8; }
        .status-ok { color:#177d60; background:#e3f8f0; }
        .status-error { color:#b74a5a; background:#ffe9ec; }
        .muted { color:#718096; font-size:.85rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def load_history() -> list[dict[str, Any]]:
    if not HISTORY_FILE.exists():
        return []
    try:
        data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        st.error(f"Saved verification history could not be loaded: {error}")
        return []
    if not isinstance(data, list):
        st.error("Saved verification history has an invalid format.")
        return []
    return data


def save_history(report: str, files: list[Any]) -> None:
    history = load_history()
    history.insert(
        0,
        {
            "label": files[0].name if len(files) == 1 else f"{len(files)} uploaded artifacts",
            "created_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
            "file_count": len(files),
            "report": report,
            "status": "Evidence incomplete",
        },
    )
    try:
        HISTORY_FILE.write_text(json.dumps(history[:50], indent=2), encoding="utf-8")
    except OSError as error:
        st.error(f"Verification completed, but the report could not be saved: {error}")


def detector_lines(selected: list[str]) -> str:
    if not selected:
        return "No AI-origin detectors selected."
    lines = []
    for detector in selected:
        if detector == "Local forensic checks":
            result = "SIGNAL UNAVAILABLE (backend parser required for this file type)"
        elif detector == "Content detector adapter":
            result = "NOT CONFIGURED (connect a detector API endpoint)"
        else:
            result = "NO MATCHING SIGNED EVENT (a changed hash cannot prove AI generation)"
        lines.append(f"- {detector}: {result}")
    return "\n".join(lines)


def create_report(uploaded_file: Any, content: bytes, selected: list[str]) -> str:
    digest = hashlib.sha256(content).hexdigest()
    created = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    report = f"""MODELLEDGER PROVENANCE REPORT
Generated: {created}

ARTIFACT
Name: {uploaded_file.name}
Type: {uploaded_file.type or "unknown"}
Size: {len(content) / 1024 / 1024:.2f} MB
SHA-256: {digest}

ORIGIN
AI-generated: Not determinable from the file alone
Specific AI system: No signed attribution found
Evidence: No connected ledger event was available for this browser-free check

TRANSFORMATION HISTORY
Recorded modifications: No verifiable transformation events found
Modified how many times: Unknown
Modified by: Unknown

MULTI-MODEL AI ORIGIN CHECK
{detector_lines(selected)}
Consensus: INCONCLUSIVE - no configured detector returned a classification

VERIFICATION NOTES
The file fingerprint was calculated locally. A definitive origin, model identity,
or modification timeline requires matching signed ModelLedger events. A changed
hash proves that the exact bytes differ; it does not by itself prove AI generation.
"""
    return report


def render_sidebar() -> tuple[str, list[str]]:
    with st.sidebar:
        st.markdown("## ◈ ModelLedger")
        st.caption("Privacy-preserving provenance verification")
        st.divider()
        st.markdown("### Workspace")
        page = st.radio("Navigate", ["Verify artifact", "Verification history"], label_visibility="collapsed")
        st.divider()
        st.success("Ledger network\n\nLocal verifier ready")
        st.caption("Files are hashed in Python memory. The original file is not uploaded by this demo.")
        selected = st.multiselect(
            "AI-origin detectors",
            options=list(DETECTORS),
            default=list(DETECTORS),
            format_func=lambda name: f"{name} - {DETECTORS[name]}",
        )
    return page, selected


def render_history() -> None:
    st.title("Verification history")
    st.caption("Reports are saved locally in verification_history.json.")
    history = load_history()
    if not history:
        st.info("Completed reports will appear here automatically.")
        return
    if st.button("Clear history", type="secondary"):
        try:
            HISTORY_FILE.unlink(missing_ok=True)
        except OSError as error:
            st.error(f"History could not be cleared: {error}")
        else:
            st.rerun()
    for index, item in enumerate(history):
        with st.expander(
            f"{item.get('label', 'Artifact')} · {item.get('created_at', 'Unknown time')} · "
            f"{item.get('file_count', 0)} file(s)"
        ):
            st.code(item.get("report", ""), language="text")
            st.download_button(
                "Download report",
                item.get("report", ""),
                file_name=f"modelledger-report-{index + 1}.txt",
                mime="text/plain",
                key=f"download-{index}",
            )


def render_verification(selected: list[str]) -> None:
    st.title("Verify an artifact")
    st.caption("Trace origin, transformations, and trust signals across your media.")
    uploaded = st.file_uploader(
        "Upload images, PDFs, or videos",
        type=["jpg", "jpeg", "png", "webp", "pdf", "mp4", "mov", "webm"],
        accept_multiple_files=True,
        help="Multiple files are supported. Maximum 250 MB per file.",
    )
    if uploaded:
        oversized = [file.name for file in uploaded if file.size > MAX_FILE_SIZE]
        if oversized:
            st.error(f"These files exceed the 250 MB limit: {', '.join(oversized)}")
            return
        st.subheader("Selected files")
        for file in uploaded:
            st.write(f"**{file.name}** · {file.type or 'unknown type'} · {file.size / 1024:.0f} KB")
        st.info("SHA-256 fingerprinting happens locally in Python memory.")
        if st.button("Verify selected files", type="primary"):
            with st.spinner("Hashing files and generating reports..."):
                reports = [create_report(file, file.getvalue(), selected) for file in uploaded]
                combined = ("\n\n" + ("-" * 65) + "\n\n").join(reports)
                save_history(combined, uploaded)
            st.session_state["latest_report"] = combined
            st.session_state["latest_count"] = len(uploaded)
            st.success("Verification complete. The report was saved to Verification history.")
    latest = st.session_state.get("latest_report")
    if latest:
        st.subheader("Readable report")
        st.markdown('<span class="status status-warning">Evidence incomplete</span>', unsafe_allow_html=True)
        st.code(latest, language="text")
        st.download_button("Download latest report", latest, "modelledger-report.txt", "text/plain")


def main() -> None:
    configure_page()
    page, selected = render_sidebar()
    if page == "Verification history":
        render_history()
    else:
        render_verification(selected)


if __name__ == "__main__":
    main()
