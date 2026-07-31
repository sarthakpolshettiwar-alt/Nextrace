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
    
    # 3. USB Session Analytics & Reconstruction
    if results.get('sessions'):
        elements.append(Paragraph("3. USB Session Analytics & Reconstruction", h1_style))
        
        analytics = results.get('analytics', {})
        if analytics:
            summary_data = [
                [Paragraph("Metric", normal_style), Paragraph("Value", normal_style), Paragraph("Metric", normal_style), Paragraph("Value", normal_style)],
                [Paragraph("Total Sessions", normal_style), Paragraph(str(analytics.get('total_sessions', 0)), normal_style), Paragraph("Completed Sessions", normal_style), Paragraph(str(analytics.get('completed_sessions', 0)), normal_style)],
                [Paragraph("Active Sessions", normal_style), Paragraph(str(analytics.get('active_sessions', 0)), normal_style), Paragraph("Unexpected Removals", normal_style), Paragraph(str(analytics.get('unexpected_removals', 0)), normal_style)],
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
