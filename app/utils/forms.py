from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SelectField, SelectMultipleField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, ValidationError, NumberRange
from app.models.user import User
from app import db
from config import Config
from app.utils.timezone_utils import get_timezone_display_name
from app.utils.sanitize import sanitize_nmap_command, sanitize_nmap_targets
import pytz

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    timezone = SelectField('Timezone', choices=[(tz, tz) for tz in Config.AVAILABLE_TIMEZONES], default='UTC')
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Length(min=8)])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[DataRequired()])
    active = BooleanField('Active')
    timezone = SelectField('Timezone', choices=[(tz, tz) for tz in Config.AVAILABLE_TIMEZONES])
    submit = SubmitField('Save')

class UserProfileForm(FlaskForm):
    """Form for users to update their profile settings"""
    timezone = SelectField('Timezone', choices=[(tz, get_timezone_display_name(tz)) for tz in Config.AVAILABLE_TIMEZONES])
    
    # Password change fields (optional)
    current_password = PasswordField('Current Password', validators=[Optional()])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[Optional(), EqualTo('new_password', message='Passwords must match')])
    
    submit = SubmitField('Update Profile')
    
    def validate(self, *args, **kwargs):
        """Custom validation to ensure password fields are properly filled"""
        # Call the parent validate method with any extra arguments
        if not super().validate(*args, **kwargs):
            return False
            
        # If any password field is filled, all password fields must be filled
        if self.current_password.data or self.new_password.data or self.confirm_password.data:
            if not self.current_password.data:
                self.current_password.errors.append('Current password is required to change password')
                return False
            if not self.new_password.data:
                self.new_password.errors.append('New password is required')
                return False
            if not self.confirm_password.data:
                self.confirm_password.errors.append('Please confirm your new password')
                return False
        
        return True

class TargetGroupForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=3, max=64)])
    description = TextAreaField('Description', validators=[Optional()])
    targets = TextAreaField('Targets (one per line)', validators=[DataRequired()])
    submit = SubmitField('Save')
    
    def validate_targets(self, targets):
        """Validate and sanitize target IP addresses and hostnames"""
        if not targets.data:
            return
            
        # Split the targets by newline
        target_list = [t.strip() for t in targets.data.split('\n')]
        target_list = [t for t in target_list if t]  # Remove empty lines
        
        # Validate each target
        valid_targets = []
        invalid_targets = []
        
        for target in target_list:
            # Use our sanitization function to validate the target
            sanitized = sanitize_nmap_targets(target)
            if sanitized:
                valid_targets.extend(sanitized)
            else:
                invalid_targets.append(target)
        
        # If there are invalid targets, raise a validation error
        if invalid_targets:
            if len(invalid_targets) == 1:
                raise ValidationError(f'Invalid target: {invalid_targets[0]}')
            else:
                raise ValidationError(f'Invalid targets: {", ".join(invalid_targets)}')
        
        # Update the form data with the sanitized targets
        targets.data = '\n'.join(valid_targets)

class ScanTaskForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=3, max=64)])
    description = TextAreaField('Description', validators=[Optional()])
    target_groups = SelectMultipleField('Target Groups', coerce=int, validators=[DataRequired()])
    
    # Create choices for scan profiles from config
    scan_profile_choices = [(k, k.replace('_', ' ').title()) for k in Config.NMAP_SCAN_PROFILES.keys()]
    scan_profile_choices.insert(0, ('custom', 'Custom Arguments'))
    
    scan_profile = SelectField('Scan Profile', choices=scan_profile_choices, validators=[DataRequired()])
    custom_args = StringField('Custom Nmap Arguments', validators=[Optional()])
    
    # Report settings
    use_global_max_reports = BooleanField('Use Global Maximum Reports Setting', default=True,
                                        description='When enabled, this task will use the system-wide setting for maximum reports')
    max_reports = IntegerField('Maximum Reports to Keep', validators=[Optional(), NumberRange(min=1, max=100)],
                             description='Maximum number of reports to keep for this task (overrides global setting)')
    
    run_now = BooleanField('Run Immediately')
    submit = SubmitField('Save')
    
    def validate_custom_args(self, custom_args):
        if self.scan_profile.data == 'custom' and not custom_args.data:
            raise ValidationError('Custom arguments are required when using custom profile.')
        
        # Use our centralized sanitization function for Nmap commands
        if custom_args.data:
            sanitized = sanitize_nmap_command(custom_args.data)
            if sanitized is None:
                raise ValidationError('The provided Nmap arguments contain potentially dangerous options or characters.')
            
            # Update the form data with the sanitized version
            custom_args.data = sanitized

class ScheduleForm(FlaskForm):
    schedule_type = SelectField('Schedule Type', choices=[
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('interval', 'Interval (Hours)')
    ], validators=[DataRequired()])
    
    # Display current timezone
    current_timezone = StringField('Current Timezone', render_kw={'readonly': True})
    
    # Daily, Weekly, Monthly fields
    hour = IntegerField('Hour (0-23)', validators=[NumberRange(min=0, max=23)], default=0)
    minute = IntegerField('Minute (0-59)', validators=[NumberRange(min=0, max=59)], default=0)
    
    # Weekly fields
    day_of_week = SelectField('Day of Week', choices=[
        (0, 'Monday'),
        (1, 'Tuesday'),
        (2, 'Wednesday'),
        (3, 'Thursday'),
        (4, 'Friday'),
        (5, 'Saturday'),
        (6, 'Sunday')
    ], coerce=int, default=0)
    
    # Monthly fields
    day = IntegerField('Day of Month (1-31)', validators=[NumberRange(min=1, max=31)], default=1)
    
    # Interval fields
    hours = IntegerField('Hours', validators=[NumberRange(min=1)], default=24)
    
    submit = SubmitField('Schedule')
    

class SystemSettingsForm(FlaskForm):
    """Form for system-wide settings"""
    max_concurrent_tasks = IntegerField('Maximum Concurrent Tasks', 
                                       validators=[NumberRange(min=1, max=20)],
                                       description='Maximum number of scan tasks that can run in parallel')
    
    max_reports_per_task = IntegerField('Maximum Reports per Task', 
                                       validators=[NumberRange(min=1, max=100)],
                                       description='Default maximum number of reports to keep for each task')
    
    pagination_rows = IntegerField('Items Per Page',
                                  validators=[NumberRange(min=5, max=100)],
                                  description='Default number of items to display per page in listings (tasks, reports, etc.)')
    
    submit = SubmitField('Save Settings')
