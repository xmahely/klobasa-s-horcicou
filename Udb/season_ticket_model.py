from app_config import db


class season_ticket(db.Model):

    ticket_id = db.Column('ticket_id', db.Integer, primary_key=True)
    season = db.Column('season', db.Integer)
    valid_from = db.Column('valid_from', db.DateTime)
    valid_to = db.Column('valid_to', db.DateTime)
    status = db.Column('status', db.Boolean, default=0)

    def __init__(self, ticket_id, season, Vfrom,to,status):
        self.ticket_id = ticket_id
        self.season = season
        self.valid_from = Vfrom
        self.valid_to = to
        self.status = status



