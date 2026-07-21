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
    
    # 3. Event Correlation
    if results.get('events'):
        elements.append(Paragraph("3. Event Log Correlation", h1_style))
        data = [[Paragraph("Timestamp", normal_style), Paragraph("Event ID", normal_style), Paragraph("Matched Device", normal_style), Paragraph("Serial Number", normal_style)]]
        for event in results['events']:
            data.append([Paragraph(event['timestamp'], normal_style), Paragraph(event['event_id'], normal_style), Paragraph(event['matched_device'], normal_style), Paragraph(event['serial_number'], normal_style)])
            
        t = Table(data, colWidths=[1.5*inch, 1.0*inch, 2.5*inch, 2.0*inch])
        t.setStyle(TableStyle(base_table_style))
        elements.append(t)
        elements.append(Spacer(1, 0.4 * inch))
        
    # Build PDF
    doc.build(elements)
    return output_path
