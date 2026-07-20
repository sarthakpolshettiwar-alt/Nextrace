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
    elements.append(Paragraph(f"NexTrace - {case_name}", title_style))
    elements.append(Spacer(1, 0.2 * inch))
    
    # Summary
    elements.append(Paragraph("Executive Summary", h1_style))
    elements.append(Paragraph(f"This report contains the forensic analysis of a Windows SYSTEM registry hive.", normal_style))
    if results.get('events'):
         elements.append(Paragraph(f"Windows Event Logs were also analyzed and correlated with registry data.", normal_style))
    elements.append(Spacer(1, 0.2 * inch))
    
    # 1. USB Devices
    elements.append(Paragraph("1. USB Devices Detected", h1_style))
    
    if results.get('devices'):
        # Table Header
        data = [["Device Name", "Vendor / Product", "Serial Number", "Last Write Time"]]
        
        for dev in results['devices']:
            dt_str = dev.last_write_time.strftime('%Y-%m-%d %H:%M:%S') if dev.last_write_time else "N/A"
            name = dev.friendly_name or "Unknown"
            vendor_prod = f"{dev.vendor} / {dev.product}"
            data.append([name, vendor_prod, dev.serial_number, dt_str])
            
        t = Table(data, colWidths=[1.5*inch, 2.0*inch, 2.0*inch, 1.5*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No USB devices found.", normal_style))
        
    elements.append(Spacer(1, 0.4 * inch))
    
    # 2. Risk Analysis
    elements.append(Paragraph("2. Risk Analysis Flags", h1_style))
    if results.get('risks'):
        data = [["Device", "Flag Reason", "Risk Level"]]
        for risk in results['risks']:
            data.append([risk['device_name'], risk['reason'], risk['level']])
            
        t = Table(data, colWidths=[2.0*inch, 3.5*inch, 1.5*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        
        # Colorize risk levels
        for i, risk in enumerate(results['risks'], start=1):
            if risk['level'] == 'High':
                t.setStyle(TableStyle([('TEXTCOLOR', (2, i), (2, i), colors.red)]))
            elif risk['level'] == 'Medium':
                t.setStyle(TableStyle([('TEXTCOLOR', (2, i), (2, i), colors.orange)]))
                
        elements.append(t)
    else:
        elements.append(Paragraph("No anomalies detected.", normal_style))
        
    elements.append(Spacer(1, 0.4 * inch))
    
    # 3. Event Correlation
    if results.get('events'):
        elements.append(Paragraph("3. Event Log Correlation", h1_style))
        data = [["Timestamp", "Event ID", "Matched Device", "Serial Number"]]
        for event in results['events']:
            data.append([event['timestamp'], event['event_id'], event['matched_device'], event['serial_number']])
            
        t = Table(data, colWidths=[1.5*inch, 1.0*inch, 2.5*inch, 2.0*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.4 * inch))
        
    # 4. Multi-Machine Matches
    elements.append(Paragraph("4. Multi-Machine Matches", h1_style))
    if results.get('matches'):
        for match in results['matches']:
            txt = f"<b>{match['device_name']}</b> (SN: {match['serial_number']}) was also seen in previously analyzed hive: <b>{match['other_hive']}</b>"
            elements.append(Paragraph(txt, normal_style))
            elements.append(Spacer(1, 0.1 * inch))
    else:
        elements.append(Paragraph("No devices have been seen across other hives.", normal_style))
        
    # Build PDF
    doc.build(elements)
    return output_path
