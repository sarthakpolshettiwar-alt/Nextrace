# Module 2 (Email Forensic Analysis) UI Manual Test Checklist

This checklist documents the manual UI and integration test cases for Module 2 of Forenix.

---

## 1. Authentication & Route Security
- [ ] **Unauthenticated Access Protection**:
  - Open a fresh browser session (or incognito window) without logging in.
  - Navigate directly to `http://localhost:5000/module2`.
  - **Expected Result**: Automatically redirected to the login page (`/login`) with an authentication requirement message.
  - Navigate directly to `http://localhost:5000/module2/results/1`.
  - **Expected Result**: Automatically redirected to the login page (`/login`).

---

## 2. File Upload Page (`/module2`)
- [ ] **Page Rendering**:
  - Log in to Forenix and click "Email Forensics" in the sidebar or dashboard.
  - **Expected Result**: Upload page renders cleanly with green accent branding (`#1a7a4c`), drag-and-drop zone, and past investigation history table.
- [ ] **Drag & Drop / File Selector**:
  - Drag an `.eml` file into the upload dropzone or select via file browser.
  - **Expected Result**: File selection badge shows filename cleanly.

---

## 3. Clean Email Upload & Forensic Results
- [ ] **Upload Clean Email (`sample_legit_gmail.eml`)**:
  - Upload `temp_samples/sample_legit_gmail.eml`.
  - Click "Run Forensic Analysis".
  - **Expected Result**: Redirected to `/module2/results/<id>`.
  - **Risk Score Card**: Displays `Low Risk` badge with score `10 / 100`.
  - **Hard Override Banner**: NOT present (`hard_flagged = False`).
  - **12-Line Audit Trail**: Shows all 12 breakdown items with `SPF: Pass (+0)` and `DMARC: Pass (+0)`.
  - **SPF / DMARC Cards**: Displays raw DNS records (`v=spf1 redirect=_spf.google.com`).
  - **Disclosed Routing Hops**: Lists raw server hops with disclaimer note.

---

## 4. Phishing Email Upload & Hard-Flag Banner
- [ ] **Upload Phishing Email (`sample_phishing.eml`)**:
  - Upload `temp_samples/sample_phishing.eml`.
  - Click "Run Forensic Analysis".
  - **Expected Result**: Redirected to `/module2/results/<id>`.
  - **Risk Score Card**: Displays `Likely Spoofed` or `High Risk` verdict badge.
  - **Hard Override Banner**: Present if both SPF and DKIM fail strictly (Red alert banner displaying reason).
  - **12-Line Audit Trail**: Shows firing rules (`SPF: SoftFail (+12)`, `DMARC: Fail (+20)`).
  - **URL Analysis Table**: Displays extracted link with `Brand impersonation mismatch` flag highlighted in red badge.

---

## 5. Invalid & Corrupt File Error Handling
- [ ] **Upload Non-Email File (e.g. `test.txt` or renamed `.txt` file)**:
  - Attempt to upload a `.txt` file or corrupt text file.
  - **Expected Result**: Flash error message displayed at top (`"Invalid file extension. Only .eml and .msg files are supported."` or `"Invalid email file: ..."`). Application does NOT crash. Upload page re-renders cleanly.

---

## 6. History & Re-visiting Past Analyses
- [ ] **Access Past Results**:
  - Return to `/module2` upload page.
  - Locate past analysis in "Recent Forensic Investigations" table.
  - Click "View Report".
  - **Expected Result**: Loads stored analysis report from SQLite `email_analyses` table with identical full JSON breakdown data intact.

---

## 7. Visual Consistency with Module 1
- [ ] **Design Audit**:
  - Compare Module 2 pages side-by-side with Module 1 (`/usb-forensic`).
  - Confirm matching sidebar, navbar header, card border radii (`rounded-2xl`), font family (`Inter`), brand green color palette (`#1a7a4c`), and Feather icons.
