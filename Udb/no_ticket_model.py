from app_config import db


class no_ticket(db.Model):
    ticket_type_id = db.Column('ticket_type_id', db.Integer, primary_key=True)
    zones = db.Column('zones', db.String(255))
    regional_zones = db.Column('regional_zones', db.String(255))
    duration = db.Column('duration', db.Integer) # uklada sa v sekundach
    duration_metric = db.Column('duration_metric',  db.String(255)) # aby sa na fe dokazal konvertovat na minuty hodiny dni
    # ma hodnoty 's', 'h' alebo 'd'
    price = db.Column('price', db.Float)
    discounted = db.Column('discounted', db.Boolean)
    season_ticket = db.Column('season_ticket', db.Boolean)  # električenka = 1, základný lístok = 0

    def __init__(self, zones, regional_zones, duration, duration_metric, price, discounted, season_ticket):
        self.zones = zones
        self.regional_zones = regional_zones
        self.duration = duration
        self.duration_metric = duration_metric
        self.price = price
        self.discounted = discounted
        self.season_ticket = season_ticket


def get_tickets():
    return no_ticket.query.filter_by(season_ticket=False).all()


def get_season_tickets():
    return no_ticket.query.filter_by(season_ticket=True).all()


def truncate_table():
    ticket_types = no_ticket.query.all()
    for type in ticket_types:
        db.session.delete(type)
    db.session.commit()


def create_ticket_types():
    truncate_table()
    durations = [30 * 60, 60 * 60, 60 * 60, 90 * 60, 90 * 60, 120 * 60, 120 * 60, 150 * 60, 150 * 60, 180 * 60,
                 24 * 60 * 60, 24 * 60 * 60,
                 72 * 60 * 60, 168 * 60 * 60]
    duration_metrics = ['m', 'm', 'm', 'm', 'm', 'm', 'm', 'm', 'm', 'm', 'h', 'h', 'h', 'h']
    zones = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'bez obmedzenia', '2', 'bez obmedzenia', '2', '2']
    prices = [0.81, 1.18, 1.49, 1.86, 2.23, 2.48, 2.68, 3.01, 3.35, 3.68, 3.7, 6.30, 8.20, 12]
    prices_discounted = [0.41, 0.59, 0.75, 0.93, 1.12, 1.24, 1.34, 1.51, 1.68, 1.84, 1.85, 3.15, 4.10, 6]
    for i in range(len(durations)):
        new_ticket = no_ticket(zones[i], None, durations[i], duration_metrics[i], prices[i], False, False)
        db.session.add(new_ticket)
        new_ticket = no_ticket(zones[i], None, durations[i], duration_metrics[i], prices_discounted[i], True, False)
        db.session.add(new_ticket)

    regional_zones = [None, '1', '2', '3', '4', '5', '6', '7']
    durations = [7 * 24 * 60 * 60, 30 * 24 * 60 * 60, 90 * 24 * 60 * 60, 365 * 24 * 60 * 60]
    prices = [[12, 30, 80, 199], [16, 40, 106.6, 265.3], [19.9, 50, 133.2, 331.6], [23.9, 60, 159.9, 397.9],
              [26.5, 66.5, 177.2, 441.1], [28.7, 72, 191.8, 477.5], [32.2, 81, 215.8, 537.2], [35.8, 90, 239.8, 596.9]]
    prices_discounted = [[6, 15, 40, 99.5], [8, 20, 53.3, 132.65], [9.95, 25, 66.6, 165.8], [11.95, 30, 79.95, 198.95],
                         [13.25, 33.25, 88.6, 220.55], [14.35, 36, 95.9, 238.75], [16.10, 40.5, 107.9, 268.6],
                         [17.9, 45, 119.9, 298.45]]
    for i in range(len(regional_zones)):
        for j in range(len(durations)):
            new_ticket = no_ticket('2', regional_zones[i], durations[j], 'd', prices[i][j], False, True)
            db.session.add(new_ticket)
            new_ticket = no_ticket('2', regional_zones[i], durations[j], 'd', prices_discounted[i][j], True, True)
            db.session.add(new_ticket)

    db.session.commit()
