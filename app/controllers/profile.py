from flask import Blueprint, render_template, redirect, url_for, flash, session, request
from flask_login import login_required, current_user
from app import db
from app.utils.forms import UserProfileForm
from app.utils.timezone_utils import get_current_time_in_user_timezone, get_timezone_display_name
from werkzeug.security import check_password_hash

profile_bp = Blueprint('profile', __name__, url_prefix='/profile')

@profile_bp.route('/', methods=['GET', 'POST'])
@login_required
def index():
    """User profile page with timezone settings"""
    form = UserProfileForm(obj=current_user)
    
    if form.validate_on_submit():
        # Update the user's timezone
        current_user.timezone = form.timezone.data
        
        # Handle password change if provided
        if form.current_password.data:
            # Verify the current password
            if not check_password_hash(current_user.password_hash, form.current_password.data):
                flash('Current password is incorrect.', 'danger')
                return render_template('profile/index.html', 
                                      title='User Profile',
                                      form=form, 
                                      current_time=get_current_time_in_user_timezone(),
                                      timezone_display=get_timezone_display_name(current_user.timezone))
            
            # Set the new password
            current_user.set_password(form.new_password.data)
            flash('Your password has been updated.', 'success')
        
        # Save changes to the database
        db.session.commit()
        
        # Update the session timezone
        session['timezone'] = current_user.timezone
        
        flash('Your profile has been updated.', 'success')
        return redirect(url_for('profile.index'))
    
    # Get current time in user's timezone for display
    current_time = get_current_time_in_user_timezone()
    timezone_display = get_timezone_display_name(current_user.timezone)
    
    return render_template('profile/index.html', 
                          title='User Profile',
                          form=form, 
                          current_time=current_time,
                          timezone_display=timezone_display)
