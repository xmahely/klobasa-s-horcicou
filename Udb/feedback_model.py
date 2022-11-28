from app_config import db


class FeedbackMessage(db.Model):
    message_id = db.Column('message_id', db.Integer, primary_key=True)
    sender_ID = db.Column(db.Integer)
    sender_name = db.Column(db.String(255))
    subject = db.Column(db.String(255))
    message = db.Column(db.String(1023))

    @staticmethod
    def create(sender_ID, sender_name, subject, message):  # create new user
        new_message = FeedbackMessage(sender_ID, sender_name, subject, message)
        db.session.add(new_message)
        db.session.commit()

    def get_id(self):
        return self.user_id

    def __init__(self, sender_ID, sender_name, subject, message):
        self.sender_ID = sender_ID
        self.subject= subject
        self.message = message
        self.sender_name = sender_name
    def selectFeedbackMessages():
        return FeedbackMessage.query.all()


