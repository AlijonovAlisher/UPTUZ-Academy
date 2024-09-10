from django.core.mail import EmailMessage
import threading


class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        super().__init__()  # Initialize the thread properly using super()

    def run(self):
        try:
            self.email.send(fail_silently=False)  # Ensure errors are not suppressed
        except Exception as e:
            # Log or handle the exception as needed
            print(f"Failed to send email: {e}")


class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data.get('email_subject', 'No Subject'),  # Provide default values
            body=data.get('email_body', ''),
            to=[data.get('to_email', '')]
        )
        if email.to:  # Check if 'to_email' was provided
            EmailThread(email).start()
        else:
            print("No recipient email address provided")
