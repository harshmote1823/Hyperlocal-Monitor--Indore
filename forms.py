from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length

# You'd typically load resources from the DB, but for simplicity here's a hardcoded list
RESOURCE_CHOICES = [
    ('Water Supply', 'Water Supply'),
    ('Electricity', 'Electricity'),
    ('Roads/Traffic', 'Roads/Traffic'),
    ('Waste Management', 'Waste Management'),
    ('Public Parks', 'Public Parks')
]

class IncidentReportForm(FlaskForm):
    resource_name = SelectField('Resource Type', choices=RESOURCE_CHOICES, validators=[DataRequired()])
    location = StringField('Affected Location (e.g., Street, Colony, Landmark)', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description of Incident', validators=[DataRequired(), Length(min=10)])
    reported_by = StringField('Your Name (Optional)', validators=[Length(max=100)])
    submit = SubmitField('Submit Report')