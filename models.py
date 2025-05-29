from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False) 

    incidents = db.relationship('IncidentReport', backref='resource', lazy=True)

    def __repr__(self):
        return f'<Resource {self.name}>'

class IncidentReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=False)
    location = db.Column(db.String(200), nullable=False) 
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='Reported') 
    reported_at = db.Column(db.DateTime, default=datetime.utcnow)
    reported_by = db.Column(db.String(100), nullable=True)

    def __repr__(self):
        return f'<Incident {self.location} - {self.status}>'