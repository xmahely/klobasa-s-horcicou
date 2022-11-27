from app_config import db

class season_ticket(db.Model):
    season_ticket_id = db.Column('season_ticket_id', db.Integer, primary_key=True)
    first_name = db.Column('first_name', db.String(255))
    last_name = db.Column('last_name', db.String(255))
    city = db.Column('city', db.String(255))
    id_card_number = db.Column('id_card_number', db.String(255))

    def __init__(self, first_name, last_name, city, id_card_number):
        self.first_name = first_name
        self.last_name = last_name
        self.city = city
        self.id_card_number = id_card_number
