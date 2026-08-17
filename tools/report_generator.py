import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

def generate_pdf_report(results, output_path, case_name="USB Forensic Analysis"):
    """
    Generates a PDF report containing the analysis results.
    """
    doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=18)
    
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    h1_style = styles['Heading1']
    h2_style = styles['Heading2']
    normal_style = styles['Normal']
    
    # Custom styles
    h1_style.textColor = colors.HexColor('#1a7a4c')
    
    elements = []
    
    # Title
    elements.append(Paragraph(f"Forenix - {case_name}", title_style))
    elements.append(Spacer(1, 0.2 * inch))
    
    # Summary
    elements.append(Paragraph("Executive Summary", h1_style))
    elements.append(Paragraph(f"This report contains the forensic analysis of a Windows SYSTEM registry hive.", normal_style))
    if results.get('events'):
         elements.append(Paragraph(f"Windows Event Logs were also analyzed and correlated with registry data.", normal_style))
    elements.append(Spacer(1, 0.1 * inch))
    note = "<b>Note:</b> Registry 'Last Write Time' reflects only the first/last registered connection. Upload both Device Configuration and Device Management event logs for accurate real-time connect/disconnect history."
    elements.append(Paragraph(note, normal_style))
    elements.append(Spacer(1, 0.2 * inch))
    
    base_table_style = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]
    
    # 1. USB Devices
    elements.append(Paragraph("1. USB Devices Detected", h1_style))
    
    if results.get('devices'):
        # Table Header
        data = [[Paragraph("Device Name", normal_style), Paragraph("Vendor / Product", normal_style), Paragraph("Serial Number", normal_style), Paragraph("Last Write Time", normal_style)]]
        
        for dev in results['devices']:
            dt_str = dev.last_write_time.strftime('%Y-%m-%d %H:%M:%S IST') if dev.last_write_time else "N/A"
            name = Paragraph(dev.friendly_name or "Unknown", normal_style)
            vendor_prod = Paragraph(f"{dev.vendor} / {dev.product}", normal_style)
            data.append([name, vendor_prod, Paragraph(dev.serial_number, normal_style), Paragraph(dt_str, normal_style)])
            
        t = Table(data, colWidths=[1.5*inch, 2.0*inch, 2.2*inch, 1.3*inch])
        t.setStyle(TableStyle(base_table_style + [('BACKGROUND', (0, 1), (-1, -1), colors.white)]))
        elements.append(t)
    else:
        elements.append(Paragraph("No USB devices found.", normal_style))
        
    elements.append(Spacer(1, 0.4 * inch))
    
    # 2. Risk Analysis
    elements.append(Paragraph("2. Risk Analysis Flags", h1_style))
    if results.get('risks'):
        data = [[Paragraph("Device", normal_style), Paragraph("Flag Reason", normal_style), Paragraph("Risk Level", normal_style)]]
        for risk in results['risks']:
            data.append([Paragraph(risk['device_name'], normal_style), Paragraph(risk['reason'], normal_style), Paragraph(risk['level'], normal_style)])
            
        t = Table(data, colWidths=[1.8*inch, 4.2*inch, 1.0*inch])
        t_style = list(base_table_style)
        
        # Colorize risk levels
        for i, risk in enumerate(results['risks'], start=1):
            if risk['level'] == 'High':
                t_style.append(('TEXTCOLOR', (2, i), (2, i), colors.red))
            elif risk['level'] == 'Medium':
                t_style.append(('TEXTCOLOR', (2, i), (2, i), colors.orange))
                
        t.setStyle(TableStyle(t_style))
        elements.append(t)
    else:
        elements.append(Paragraph("No anomalies detected.", normal_style))
        
    elements.append(Spacer(1, 0.4 * inch))
    
    # 3. USB Session Analytics & Reconstruction
    if results.get('sessions'):
        elements.append(Paragraph("3. USB Session Analytics & Reconstruction", h1_style))
        
        analytics = results.get('analytics', {})
        if analytics:
            summary_data = [
                [Paragraph("Metric", normal_style), Paragraph("Value", normal_style), Paragraph("Metric", normal_style), Paragraph("Value", normal_style)],
                [Paragraph("Total Sessions", normal_style), Paragraph(str(analytics.get('total_sessions', 0)), normal_style), Paragraph("Completed Sessions", normal_style), Paragraph(str(analytics.get('completed_sessions', 0)), normal_style)],
                [Paragraph("Active Sessions", normal_style), Paragraph(str(analytics.get('active_sessions', 0)), normal_style), Paragraph("Disconnected", normal_style), Paragraph(str(analytics.get('unexpected_removals', 0)), normal_style)],

                [Paragraph("Average Duration", normal_style), Paragraph(str(analytics.get('average_duration_formatted', 'N/A')), normal_style), Paragraph("Total Connected Time", normal_style), Paragraph(str(analytics.get('total_connected_time_formatted', 'N/A')), normal_style)],
            ]
            sum_t = Table(summary_data, colWidths=[1.8*inch, 1.7*inch, 1.8*inch, 1.7*inch])
            sum_t.setStyle(TableStyle(base_table_style))
            elements.append(sum_t)
            elements.append(Spacer(1, 0.2 * inch))

        session_table_data = [[Paragraph("Session ID", normal_style), Paragraph("Device", normal_style), Paragraph("Status", normal_style), Paragraph("Duration", normal_style), Paragraph("Connected", normal_style), Paragraph("Disconnected", normal_style)]]
        
        for sess in results['sessions']:
            s_dict = sess.to_dict() if hasattr(sess, 'to_dict') else sess
            session_table_data.append([
                Paragraph(s_dict.get('session_id', ''), normal_style),
                Paragraph(s_dict.get('device_name', ''), normal_style),
                Paragraph(s_dict.get('status', ''), normal_style),
                Paragraph(s_dict.get('duration_formatted', ''), normal_style),
                Paragraph(s_dict.get('connected_timestamp') or 'N/A', normal_style),
                Paragraph(s_dict.get('disconnected_timestamp') or 'N/A', normal_style)
            ])
            
        st_t = Table(session_table_data, colWidths=[1.1*inch, 1.7*inch, 1.1*inch, 1.0*inch, 1.1*inch, 1.0*inch])
        st_t.setStyle(TableStyle(base_table_style))
        elements.append(st_t)
        elements.append(Spacer(1, 0.4 * inch))
        
    # Build PDF
    doc.build(elements)
    return output_path


def generate_email_pdf_report(analysis_data, output_path, case_name="Email Forensic Analysis"):
    """
    Generates a ReportLab PDF report containing Module 2 Email Forensic Analysis results.
    """
    doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=18)
    styles = getSampleStyleSheet()
    
    title_style = styles['Title']
    h1_style = styles['Heading1']
    h2_style = styles['Heading2']
    normal_style = styles['Normal']

    h1_style.textColor = colors.HexColor('#1a7a4c')
    h2_style.textColor = colors.HexColor('#1a7a4c')
    
    elements = []

    # PAGE 1: SIMPLE SUMMARY (CONSUMER EXECUTIVE VIEW)
    elements.append(Paragraph(f"Forenix - {case_name}", title_style))
    elements.append(Paragraph("<b>Page 1: Executive Simple Summary</b>", h2_style))
    elements.append(Spacer(1, 0.1 * inch))

    # Metadata Banner
    meta = analysis_data.get('metadata', {})
    parsed_email = analysis_data.get('parsed_email', {})
    auth_result = analysis_data.get('auth_result', {})
    domain_result = analysis_data.get('domain_result', {})
    url_result = analysis_data.get('url_result', {})
    risk_result = analysis_data.get('risk_result', {})
    att_res = analysis_data.get('attachment_result', {})

    filename = meta.get('filename', 'email_sample.eml')
    from_addr = parsed_email.get('from_address', 'N/A')
    subject_txt = parsed_email.get('subject', '(No Subject)')
    
    meta_p = Paragraph(f"<b>File:</b> {filename} &bull; <b>From:</b> {from_addr}<br/><b>Subject:</b> {subject_txt}", normal_style)
    elements.append(meta_p)
    elements.append(Spacer(1, 0.15 * inch))

    base_table_style = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d1d5db')),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]

    # HARD OVERRIDE BANNER
    if risk_result.get('hard_flagged'):
        reason = risk_result.get('hard_flag_reason', 'Both SPF and DKIM authentication checks failed.')
        hard_banner = [
            [Paragraph("<b>CRITICAL HARD OVERRIDE FLAGGED &bull; LIKELY SPOOFED</b>", ParagraphStyle('HardWarnTitle', parent=normal_style, textColor=colors.HexColor('#991b1b'), fontSize=10, leading=12))],
            [Paragraph(f"<b>Reason:</b> {reason}", ParagraphStyle('HardWarnDesc', parent=normal_style, textColor=colors.HexColor('#7f1d1d'), fontSize=8, leading=10))]
        ]
        hb_table = Table(hard_banner, colWidths=[7.0*inch])
        hb_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fee2e2')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#ef4444')),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(hb_table)
        elements.append(Spacer(1, 0.2 * inch))

    # Executive Verdict Summary
    score = risk_result.get('total_score', 0)
    band = risk_result.get('risk_band', 'Unknown')
    verdict_explanation = risk_result.get('verdict_explanation', 'Email forensic evaluation complete.')

    verdict_summary_data = [
        [Paragraph("Risk Score", normal_style), Paragraph(f"<b>{score} / 100</b>", normal_style), Paragraph("Verdict Band", normal_style), Paragraph(f"<b>{band}</b>", normal_style)],
        [Paragraph("Plain-English Assessment", normal_style), Paragraph(f"<b>{verdict_explanation}</b>", normal_style), Paragraph("Hard Flag", normal_style), Paragraph("YES" if risk_result.get('hard_flagged') else "NO", normal_style)],
    ]
    vt_table = Table(verdict_summary_data, colWidths=[1.5*inch, 2.0*inch, 1.3*inch, 2.2*inch])
    vt_table.setStyle(TableStyle(base_table_style))
    elements.append(vt_table)
    elements.append(Spacer(1, 0.25 * inch))

    # Attachment Risk Summary on Page 1
    elements.append(Paragraph("Attachment Risk Summary", h2_style))
    attachments_list = att_res.get('attachments', [])
    if attachments_list:
        att_summary_data = [[Paragraph("Filename", normal_style), Paragraph("Size", normal_style), Paragraph("Claimed Ext", normal_style), Paragraph("Risk Assessment", normal_style)]]
        for att in attachments_list:
            fn_p = Paragraph(f"<b>{att.get('filename', '')}</b>", normal_style)
            sz_p = Paragraph(f"{att.get('size', 0)} bytes", normal_style)
            ext_p = Paragraph(str(att.get('claimed_extension', '')), normal_style)
            flg_str = "; ".join(att.get('flags', [])) or "Clean / Safe"
            flgs_p = Paragraph(f"<b>{flg_str}</b>", normal_style)
            att_summary_data.append([fn_p, sz_p, ext_p, flgs_p])

        att_sum_tbl = Table(att_summary_data, colWidths=[2.2*inch, 1.2*inch, 1.2*inch, 2.4*inch])
        att_sum_tbl.setStyle(TableStyle(base_table_style))
        elements.append(att_sum_tbl)
    else:
        elements.append(Paragraph("No attachments were found in this email.", normal_style))

    # END OF PAGE 1 -> PAGEBREAK TO FULL TECHNICAL AUDIT
    elements.append(PageBreak())

    # PAGE 2+: FULL TECHNICAL AUDIT
    elements.append(Paragraph(f"Forenix - {case_name}", title_style))
    elements.append(Paragraph("<b>Page 2+: Full Technical Audit & Detailed Breakdown</b>", h2_style))
    elements.append(Spacer(1, 0.1 * inch))

    # 1. Executive Risk Verdict & 12-Line Audit Breakdown
    elements.append(Paragraph("1. Detailed Audit Trail Breakdown (12 Rules)", h1_style))
    
    raw_pts = risk_result.get('raw_score', 0)
    hard_flg = "YES" if risk_result.get('hard_flagged') else "NO"

    verdict_summary_data_p2 = [
        [Paragraph("Clamped Risk Score", normal_style), Paragraph(f"<b>{score} / 100</b>", normal_style), Paragraph("Risk Verdict Band", normal_style), Paragraph(f"<b>{band}</b>", normal_style)],
        [Paragraph("Raw Uncapped Points", normal_style), Paragraph(f"{raw_pts} pts", normal_style), Paragraph("Hard Override Flagged", normal_style), Paragraph(hard_flg, normal_style)],
    ]
    vt_table_p2 = Table(verdict_summary_data_p2, colWidths=[1.8*inch, 1.7*inch, 1.8*inch, 1.7*inch])
    vt_table_p2.setStyle(TableStyle(base_table_style))
    elements.append(vt_table_p2)
    elements.append(Spacer(1, 0.15 * inch))

    # 12-Line Audit Trail Breakdown Table
    breakdown_data = [[Paragraph("Category", normal_style), Paragraph("Rule Checked", normal_style), Paragraph("Evaluated State", normal_style), Paragraph("Points Added", normal_style)]]

    for item in risk_result.get('breakdown', []):
        cat = Paragraph(item.get('category', ''), normal_style)
        rule = Paragraph(item.get('rule_name', ''), normal_style)
        state = Paragraph(str(item.get('state', '')), normal_style)
        pts = Paragraph(f"+{item.get('points_added', 0)}", normal_style)
        breakdown_data.append([cat, rule, state, pts])

    bt_table = Table(breakdown_data, colWidths=[1.5*inch, 2.5*inch, 2.0*inch, 1.0*inch])
    bt_table.setStyle(TableStyle(base_table_style))
    elements.append(bt_table)
    elements.append(Spacer(1, 0.3 * inch))

    # 2. Envelope & Header Summary
    elements.append(Paragraph("2. Email Envelope & Header Summary", h1_style))
    hdr_data = [
        [Paragraph("From Display Name", normal_style), Paragraph(str(parsed_email.get('from_name') or 'N/A'), normal_style), Paragraph("From Address", normal_style), Paragraph(str(parsed_email.get('from_address') or 'N/A'), normal_style)],
        [Paragraph("Recipient (To)", normal_style), Paragraph(str(parsed_email.get('to') or 'N/A'), normal_style), Paragraph("Subject", normal_style), Paragraph(str(parsed_email.get('subject') or 'N/A'), normal_style)],
        [Paragraph("Return-Path", normal_style), Paragraph(str(parsed_email.get('return_path') or 'N/A'), normal_style), Paragraph("Reply-To", normal_style), Paragraph(str(parsed_email.get('reply_to') or 'N/A'), normal_style)],
        [Paragraph("Date", normal_style), Paragraph(str(parsed_email.get('date') or 'N/A'), normal_style), Paragraph("Message-ID", normal_style), Paragraph(str(parsed_email.get('message_id') or 'N/A'), normal_style)],
    ]
    hdr_table = Table(hdr_data, colWidths=[1.5*inch, 2.0*inch, 1.5*inch, 2.0*inch])
    hdr_table.setStyle(TableStyle(base_table_style))
    elements.append(hdr_table)
    elements.append(Spacer(1, 0.3 * inch))

    # 3. Authentication Checks
    elements.append(Paragraph("3. Authentication Validation (SPF / DKIM / DMARC)", h1_style))
    spf = auth_result.get('spf', {})
    dkim = auth_result.get('dkim', {})
    dmarc = auth_result.get('dmarc', {})

    auth_table_data = [
        [Paragraph("Check", normal_style), Paragraph("Status", normal_style), Paragraph("Domain Checked", normal_style), Paragraph("Raw TXT Record / Details", normal_style)],
        [Paragraph("SPF", normal_style), Paragraph(spf.get('status') or 'Not available', normal_style), Paragraph(spf.get('domain_checked') or 'Not available', normal_style), Paragraph(spf.get('raw_record') or spf.get('details') or 'Not available', normal_style)],
        [Paragraph("DKIM", normal_style), Paragraph(dkim.get('status') or 'Not available', normal_style), Paragraph(dkim.get('domain_checked') or 'Not available', normal_style), Paragraph(dkim.get('reason') or 'Not available', normal_style)],
        [Paragraph("DMARC", normal_style), Paragraph(dmarc.get('status') or 'Not available', normal_style), Paragraph(dmarc.get('domain_checked') or 'Not available', normal_style), Paragraph(dmarc.get('raw_record') or f"Policy p={dmarc.get('policy') or 'none'}", normal_style)],
    ]
    at_table = Table(auth_table_data, colWidths=[1.0*inch, 1.2*inch, 1.8*inch, 3.0*inch])
    at_table.setStyle(TableStyle(base_table_style))
    elements.append(at_table)
    elements.append(Spacer(1, 0.3 * inch))

    # 4. Domain Intelligence
    elements.append(Paragraph("4. Domain Intelligence & Impersonation", h1_style))
    bd = domain_result.get('domain_breakdown') or {}
    dom_data = [
        [Paragraph("Subdomain", normal_style), Paragraph(bd.get('subdomain') or '(none)', normal_style), Paragraph("Domain Label", normal_style), Paragraph(bd.get('domain') or 'Not available', normal_style)],
        [Paragraph("Public Suffix", normal_style), Paragraph(bd.get('suffix') or 'Not available', normal_style), Paragraph("Registered Domain", normal_style), Paragraph(bd.get('registered_domain') or 'Not available', normal_style)],
        [Paragraph("Sender Typosquatting", normal_style), Paragraph("FLAGGED" if domain_result.get('is_typosquat') else "PASS (Checked vs 38 brands)", normal_style), Paragraph("Punycode/Homograph", normal_style), Paragraph("FLAGGED" if domain_result.get('is_homograph') else "PASS", normal_style)],
    ]
    dt_table = Table(dom_data, colWidths=[1.5*inch, 2.0*inch, 1.5*inch, 2.0*inch])
    dt_table.setStyle(TableStyle(base_table_style))
    elements.append(dt_table)
    elements.append(Spacer(1, 0.05 * inch))
    elements.append(Paragraph("<b>Note:</b> Similarity-based check against curated brand list — not a guarantee of impersonation.", ParagraphStyle('DetectionNote', parent=normal_style, fontSize=7, textColor=colors.HexColor('#4b5563'))))
    elements.append(Spacer(1, 0.25 * inch))

    # 5. URL & Link Analysis
    elements.append(Paragraph("5. Extracted URLs & Link Analysis", h1_style))
    links = url_result.get('links', [])
    if links:
        url_table_data = [[Paragraph("Visible Link Text", normal_style), Paragraph("Actual Destination URL", normal_style), Paragraph("Analysis Flags", normal_style)]]
        for link in links:
            txt = Paragraph(link.get('link_text', ''), normal_style)
            dest = Paragraph(link.get('destination_url', ''), normal_style)
            flg_str = "; ".join(link.get('flags', [])) or "Clean"
            flg = Paragraph(flg_str, normal_style)
            url_table_data.append([txt, dest, flg])

        ut_table = Table(url_table_data, colWidths=[2.2*inch, 2.5*inch, 2.3*inch])
        ut_table.setStyle(TableStyle(base_table_style))
        elements.append(ut_table)
    else:
        elements.append(Paragraph("No URLs extracted from email body.", normal_style))

    elements.append(Spacer(1, 0.3 * inch))

    # 6. Attachment Risk Analysis
    elements.append(Paragraph("6. Attachment Risk Analysis", h1_style))
    att_res = analysis_data.get('attachment_result', {})
    attachments_list = att_res.get('attachments', [])
    if attachments_list:
        att_table_data = [[Paragraph("Filename & Size", normal_style), Paragraph("Claimed Ext", normal_style), Paragraph("Detected MIME Type", normal_style), Paragraph("Analysis Flags", normal_style)]]
        for att in attachments_list:
            fn_str = f"<b>{att.get('filename', '')}</b><br/>{att.get('size', 0)} bytes"
            fn_p = Paragraph(fn_str, normal_style)
            ext_p = Paragraph(str(att.get('claimed_extension', '')), normal_style)
            mime_p = Paragraph(str(att.get('detected_mime', '')), normal_style)
            flgs_str = "; ".join(att.get('flags', [])) or "Clean"
            flgs_p = Paragraph(flgs_str, normal_style)
            att_table_data.append([fn_p, ext_p, mime_p, flgs_p])

        at_tbl = Table(att_table_data, colWidths=[2.0*inch, 1.0*inch, 2.0*inch, 2.0*inch])
        at_tbl.setStyle(TableStyle(base_table_style))
        elements.append(at_tbl)
    else:
        elements.append(Paragraph("No attachments found in this email.", normal_style))

    elements.append(Spacer(1, 0.3 * inch))

    # 7. Disclosed Routing Hops
    elements.append(Paragraph("7. Disclosed Received Routing Hops", h1_style))
    elements.append(Paragraph("<b>Note:</b> These routing hops represent raw disclosed server headers and are not automatically scored.", normal_style))
    elements.append(Spacer(1, 0.1 * inch))

    hops = parsed_email.get('received_headers', [])
    if hops:
        hop_data = [[Paragraph("#", normal_style), Paragraph("Raw Received Header String", normal_style)]]
        for idx, hop in enumerate(hops, start=1):
            hop_data.append([Paragraph(str(idx), normal_style), Paragraph(hop, normal_style)])

        ht_table = Table(hop_data, colWidths=[0.5*inch, 6.5*inch])
        ht_table.setStyle(TableStyle(base_table_style))
        elements.append(ht_table)
    else:
        elements.append(Paragraph("No Received: routing headers found in email.", normal_style))

    # Build PDF
    doc.build(elements)
    return output_path

