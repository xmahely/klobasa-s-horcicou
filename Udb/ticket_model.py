from app_config import db


class ticket(db.Model):

    ticket_id = db.Column('ticket_id', db.Integer, primary_key=True)
    time = db.Column('time', db.Integer)
    valid_from = db.Column('valid_from', db.DateTime)
    valid_to = db.Column('valid_to', db.DateTime)
    # QR kód

    def __init__(self, ticket_id, time, Vfrom, to):
        self.ticket_id = ticket_id
        self.time = time
        self.valid_from = Vfrom
        self.valid_to = to
