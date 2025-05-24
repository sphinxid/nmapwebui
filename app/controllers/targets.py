from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.target import TargetGroup, Target
from app.models.settings import SystemSettings
from app.utils.forms import TargetGroupForm
from app.utils.validators import validate_targets
from app.utils.sanitize import sanitize_form_data, sanitize_nmap_targets
import re

targets_bp = Blueprint('targets', __name__, url_prefix='/targets')

@targets_bp.route('/')
@targets_bp.route('/page/<int:page>')
@login_required
def index(page=1):
    # Get pagination settings from system settings
    per_page = SystemSettings.get_int('pagination_rows', 20)

    # Get search query from request
    search = request.args.get('search', '', type=str).strip()

    # Build base query
    query = TargetGroup.query.filter_by(user_id=current_user.id)
    if search:
        # Case-insensitive search on name or description
        search_pattern = f"%{search}%"
        query = query.filter(
            (TargetGroup.name.ilike(search_pattern)) |
            (TargetGroup.description.ilike(search_pattern))
        )
    query = query.order_by(TargetGroup.name)

    # For SQLite compatibility, get all results and paginate in Python
    all_target_groups = query.all()
    total_groups = len(all_target_groups)
    total_pages = (total_groups + per_page - 1) // per_page  # Ceiling division

    # Ensure page is within valid range
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages

    # Apply pagination manually
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    target_groups = all_target_groups[start_idx:end_idx]

    return render_template('targets/index.html',
                          title='Target Groups',
                          target_groups=target_groups,
                          pagination={
                              'page': page,
                              'per_page': per_page,
                              'total_pages': total_pages,
                              'total_items': total_groups
                          },
                          search=search)

@targets_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = TargetGroupForm()
    
    if form.validate_on_submit():
        # Sanitize form data
        form_data = sanitize_form_data({
            'name': form.name.data,
            'description': form.description.data,
            'targets': form.targets.data
        })
        
        # Create new target group
        target_group = TargetGroup(
            name=form_data['name'],
            description=form_data['description'],
            user_id=current_user.id
        )
        db.session.add(target_group)
        db.session.flush()  # Get the target group ID
        
        # Process targets - form.validate_targets already sanitized the targets
        # but we'll use the sanitized version from the form data
        targets_text = form_data['targets']
        # Split by both newlines and commas
        targets_raw = re.split(r'[,\n]', targets_text)
        targets_list = [t.strip() for t in targets_raw if t.strip()]
        
        # Validate targets
        valid_targets, invalid_targets = validate_targets(targets_list)
        
        if invalid_targets:
            flash(f'The following targets are invalid and were not added: {", ".join(invalid_targets)}', 'warning')
        
        # Add valid targets to the group
        for target_value, target_type in valid_targets:
            target = Target(
                value=target_value,
                target_type=target_type,
                target_group_id=target_group.id
            )
            db.session.add(target)
        
        db.session.commit()
        flash('Target group created successfully!', 'success')
        return redirect(url_for('targets.index'))
    
    return render_template('targets/create.html', title='Create Target Group', form=form)

@targets_bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    target_group = TargetGroup.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    form = TargetGroupForm(obj=target_group)
    
    # Pre-populate targets field with existing targets
    if request.method == 'GET':
        targets_text = '\n'.join([target.value for target in target_group.targets])
        form.targets.data = targets_text
    
    if form.validate_on_submit():
        # Sanitize form data
        form_data = sanitize_form_data({
            'name': form.name.data,
            'description': form.description.data,
            'targets': form.targets.data
        })
        
        target_group.name = form_data['name']
        target_group.description = form_data['description']
        
        # Process targets - form.validate_targets already sanitized the targets
        # but we'll use the sanitized version from the form data
        targets_text = form_data['targets']
        # Split by both newlines and commas
        targets_raw = re.split(r'[,\n]', targets_text)
        targets_list = [t.strip() for t in targets_raw if t.strip()]
        
        # Validate targets
        valid_targets, invalid_targets = validate_targets(targets_list)
        
        if invalid_targets:
            flash(f'The following targets are invalid and were not added: {", ".join(invalid_targets)}', 'warning')
        
        # Remove all existing targets
        Target.query.filter_by(target_group_id=target_group.id).delete()
        
        # Add valid targets to the group
        for target_value, target_type in valid_targets:
            target = Target(
                value=target_value,
                target_type=target_type,
                target_group_id=target_group.id
            )
            db.session.add(target)
        
        db.session.commit()
        flash('Target group updated successfully!', 'success')
        return redirect(url_for('targets.index'))
    
    return render_template('targets/edit.html', title='Edit Target Group', form=form, target_group=target_group)

@targets_bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    target_group = TargetGroup.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    
    # Check if target group is used in any scan tasks
    if target_group.scan_tasks.count() > 0:
        flash('Cannot delete target group that is used in scan tasks.', 'danger')
        return redirect(url_for('targets.index'))
    
    db.session.delete(target_group)
    db.session.commit()
    
    flash('Target group deleted successfully!', 'success')
    return redirect(url_for('targets.index'))

@targets_bp.route('/<int:id>/view')
@login_required
def view(id):
    target_group = TargetGroup.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    return render_template('targets/view.html', title=f'Target Group: {target_group.name}', target_group=target_group)

@targets_bp.route('/api/list')
@login_required
def api_list():
    target_groups = TargetGroup.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': tg.id,
        'name': tg.name,
        'description': tg.description,
        'target_count': tg.targets.count()
    } for tg in target_groups])
