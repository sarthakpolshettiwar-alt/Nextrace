import os
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content
from dotenv import load_dotenv
import logging

load_dotenv()
logger = logging.getLogger(__name__)

def send_otp_email(to_email: str, otp_code: str) -> bool:
    api_key = os.environ.get('SENDGRID_API_KEY')
    sender_email = os.environ.get('SENDER_EMAIL')
    
    if not api_key or not sender_email:
        logger.error("SENDGRID_API_KEY or SENDER_EMAIL environment variable is not set.")
        return False
        
    sg = sendgrid.SendGridAPIClient(api_key=api_key)
    
    subject = "Your NexTrace Password Reset Code"
    body_text = f"""
Hello,

You have requested to reset your password.
Your 6-digit verification code is: {otp_code}

This code expires in 10 minutes. Please do not share it with anyone.

If you did not request this reset, you can safely ignore this email.

Thanks,
NexTrace Team
"""
    
    from_email = Email(sender_email)
    to_email_obj = To(to_email)
    content = Content("text/plain", body_text)
    
    mail = Mail(from_email, to_email_obj, subject, content)
    
    try:
        response = sg.client.mail.send.post(request_body=mail.get())
        if 200 <= response.status_code < 300:
            return True
        else:
            logger.error(f"SendGrid returned status code: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Failed to send email via SendGrid: {str(e)}")
        return False
