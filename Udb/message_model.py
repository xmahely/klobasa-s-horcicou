from app_config import db


class Message(db.Model):
    message_id = db.Column('message_id', db.Integer, primary_key=True)
    sender_ID = db.Column(db.Integer)
    recipient_ID = db.Column(db.Integer)
    messageLocation = db.Column(db.String(255))

    @staticmethod
    def create(sender_ID, recipient_ID, messageLocation):  # create new user
        new_message = Message(sender_ID, recipient_ID, messageLocation)
        db.session.add(new_message)
        db.session.commit()

    def get_id(self):
        return self.user_id

    def __init__(self, sender_ID, recipient_ID, messageLocation):
        self.sender_ID = sender_ID
        self.recipient_ID = recipient_ID
        self.messageLocation = messageLocation

    def selectMessages(user_ID):
        # s = select(Message.recipient_ID).where(Message.sender_ID == user_ID)
        s = Message.query.filter((Message.sender_ID == user_ID) | (Message.recipient_ID == user_ID)).all()
        # s += Message.query.filter_by(recipient_ID=1).all()

        return s
