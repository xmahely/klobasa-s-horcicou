from sqlalchemy import or_, and_

from app_config import db
from Udb.no_ticket_model import no_ticket
from Udb.season_ticket import season_ticket
from Udb.user_model import User
from datetime import datetime, timedelta
from pytz import utc


class ticket(db.Model):
    ticket_id = db.Column('ticket_id', db.Integer, primary_key=True)
    ticket_type = db.Column('ticket_type', db.Integer, db.ForeignKey(no_ticket.ticket_type_id))
    season_ticket = db.Column('season_ticket_id', db.Integer, db.ForeignKey(season_ticket.season_ticket_id))
    user_id = db.Column('user_id', db.Integer, db.ForeignKey(User.user_id))
    valid_from = db.Column('valid_from', db.DateTime, default=datetime.now().replace(tzinfo=utc))
    valid_to = db.Column('valid_to', db.DateTime)
    is_valid = db.Column('is_valid', db.Boolean, default=True)
    qr_text = db.Column('qr_text', db.String(255))

    def __init__(self, ticket_type, user_id, valid_from, valid_to, qr_text, season_ticket):
        self.ticket_type = ticket_type
        self.user_id = user_id
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.qr_text = qr_text
        self.season_ticket = season_ticket


# získa všetky lístky ktoré sú aktívne
def get_user_tickets(user_id):
    tag_inactive_tickets()
    result = ticket.query.join(no_ticket, ticket.ticket_type==no_ticket.ticket_type_id)\
        .filter(ticket.user_id==user_id)\
        .filter(ticket.is_valid==True)\
        .filter(no_ticket.season_ticket==False).all()
    return result

    # return ticket.query.filter_by(user_id=user_id, is_valid=True).all()


# získa všetky električenky ktoré sú aktívne
def get_user_season_tickets(user_id):
    tag_inactive_tickets()
    result = ticket.query.join(no_ticket, ticket.ticket_type==no_ticket.ticket_type_id)\
        .filter(ticket.user_id==user_id)\
        .filter(ticket.is_valid==True)\
        .filter(no_ticket.season_ticket==True).all()
    return result


def tag_inactive_tickets():
    time = datetime.now().replace(tzinfo=utc)
    inactive_tickets = ticket.query.filter_by(is_valid=True).filter(ticket.valid_to <= time).all()
    for t in inactive_tickets:
        t.is_valid = False
        db.session.add(t)
    db.session.commit()


def create_new_season(user_id, ticket_type, first_name, last_name, city, id_card_number):
    season = season_ticket(first_name, last_name, city, id_card_number)
    db.session.add(season)
    db.session.commit()
    create_new(user_id, ticket_type, season_ticket_id=season.season_ticket_id,
               qr=f".For : {first_name} {last_name} living in {city}, id card: {id_card_number}")


def create_new(user_id, ticket_type, season_ticket_id=None, qr=""):
    ticket_type = no_ticket.query.filter_by(ticket_type_id=ticket_type).first()
    if ticket_type.duration_metric == 'm':
        duration = '{:0.0f}'.format(ticket_type.duration / 60) + ' minutes'
    elif ticket_type.duration_metric == 'h':
        duration = '{:0.0f}'.format(ticket_type.duration / 3600) + ' hours'
    else:
        duration = '{:0.0f}'.format(ticket_type.duration / (3600 * 24)) + ' days'

    discounted = " discounted " if ticket_type.discounted else ""
    season_ticket = " season " if ticket_type.season_ticket else ""

    valid_from = datetime.now().replace(tzinfo=utc)
    valid_to = valid_from + timedelta(seconds=ticket_type.duration)

    qr_text = f"Valid{discounted}{season_ticket} ticket for {duration}, for zones: {ticket_type.zones}, " \
              f"regional zones: {ticket_type.regional_zones}, from {valid_from} to {valid_to}. For user {user_id}"+qr

    new_ticket = ticket(ticket_type.ticket_type_id, user_id, valid_from, valid_to, qr_text, season_ticket_id)
    db.session.add(new_ticket)
    db.session.commit()
