from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, send_file, make_response
from flask_login import login_required, current_user
from app import db
from app.models.task import ScanRun
from app.models.report import ScanReport, HostFinding, PortFinding
from app.models.settings import SystemSettings
import os
import json
import tempfile
from io import BytesIO

# Try to import WeasyPrint, but provide a fallback if it's not available
try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False
    print("WeasyPrint is not available. PDF export functionality will be disabled.")
    print("To enable PDF export, install the required system dependencies:")
    print("  For Ubuntu/Debian: sudo apt-get install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libpangocairo-1.0-0")
    print("  For more information, see: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation")

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')

@reports_bp.route('/')
@reports_bp.route('/page/<int:page>')
@login_required
def index(page=1):
    # Get pagination settings from system settings
    per_page = SystemSettings.get_int('pagination_rows', 20)
    
    # Get all scan runs with reports for the current user
    # For SQLite compatibility, we'll get all results and paginate in Python
    all_scan_runs = ScanRun.query.join(ScanReport).join(ScanRun.task).filter(
        ScanRun.task.has(user_id=current_user.id)
    ).order_by(ScanRun.started_at.desc()).all()
    
    # Get total count
    total_reports = len(all_scan_runs)
    
    # Calculate total pages
    total_pages = (total_reports + per_page - 1) // per_page  # Ceiling division
    
    # Ensure page is within valid range
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages
    
    # Apply pagination manually
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    scan_runs = all_scan_runs[start_idx:end_idx]
    
    return render_template('reports/index.html', 
                          title='Scan Reports', 
                          scan_runs=scan_runs,
                          pagination={
                              'page': page,
                              'per_page': per_page,
                              'total_pages': total_pages,
                              'total_items': total_reports
                          })

@reports_bp.route('/<int:run_id>')
@login_required
def view(run_id):
    # Get the scan run and ensure it belongs to the current user
    scan_run = ScanRun.query.join(ScanRun.task).filter(
        ScanRun.id == run_id,
        ScanRun.task.has(user_id=current_user.id)
    ).first_or_404()
    
    # Get the report
    report = ScanReport.query.filter_by(scan_run_id=scan_run.id).first_or_404()
    
    # Parse summary if it exists
    summary = None
    if report.summary:
        summary = json.loads(report.summary)
    
    # Get host findings
    hosts = HostFinding.query.filter_by(report_id=report.id).all()
    
    return render_template(
        'reports/view.html',
        title=f'Scan Report: {scan_run.task.name}',
        scan_run=scan_run,
        report=report,
        summary=summary,
        hosts=hosts
    )

@reports_bp.route('/<int:run_id>/host/<int:host_id>')
@login_required
def view_host(run_id, host_id):
    # Get the scan run and ensure it belongs to the current user
    scan_run = ScanRun.query.join(ScanRun.task).filter(
        ScanRun.id == run_id,
        ScanRun.task.has(user_id=current_user.id)
    ).first_or_404()
    
    # Get the report
    report = ScanReport.query.filter_by(scan_run_id=scan_run.id).first_or_404()
    
    # Get the host finding
    host = HostFinding.query.filter_by(id=host_id, report_id=report.id).first_or_404()
    
    # Get port findings for this host
    ports = PortFinding.query.filter_by(host_id=host.id).order_by(PortFinding.port_number).all()
    
    # Parse OS info if it exists
    os_info = None
    if host.os_info:
        os_info = json.loads(host.os_info)
    
    return render_template(
        'reports/host.html',
        title=f'Host Details: {host.ip_address}',
        scan_run=scan_run,
        report=report,
        host=host,
        ports=ports,
        os_info=os_info
    )

@reports_bp.route('/<int:run_id>/raw/xml')
@login_required
def raw_xml(run_id):
    # Get the scan run and ensure it belongs to the current user
    scan_run = ScanRun.query.join(ScanRun.task).filter(
        ScanRun.id == run_id,
        ScanRun.task.has(user_id=current_user.id)
    ).first_or_404()
    
    # Get the report
    report = ScanReport.query.filter_by(scan_run_id=scan_run.id).first_or_404()
    
    if not report.xml_report_path or not os.path.exists(report.xml_report_path):
        flash('XML report file not found.', 'danger')
        return redirect(url_for('reports.view', run_id=run_id))
    
    return send_file(
        report.xml_report_path,
        mimetype='application/xml',
        as_attachment=True,
        download_name=f'nmap_report_{run_id}_UTC.xml'
    )

@reports_bp.route('/<int:run_id>/raw/text')
@login_required
def raw_text(run_id):
    # Get the scan run and ensure it belongs to the current user
    scan_run = ScanRun.query.join(ScanRun.task).filter(
        ScanRun.id == run_id,
        ScanRun.task.has(user_id=current_user.id)
    ).first_or_404()
    
    # Get the report
    report = ScanReport.query.filter_by(scan_run_id=scan_run.id).first_or_404()
    
    if not report.normal_report_path or not os.path.exists(report.normal_report_path):
        flash('Text report file not found.', 'danger')
        return redirect(url_for('reports.view', run_id=run_id))
    
    return send_file(
        report.normal_report_path,
        mimetype='text/plain',
        as_attachment=True,
        download_name=f'nmap_report_{run_id}_UTC.txt'
    )

@reports_bp.route('/api/summary/<int:run_id>')
@login_required
def api_summary(run_id):
    # Get the scan run and ensure it belongs to the current user
    scan_run = ScanRun.query.join(ScanRun.task).filter(
        ScanRun.id == run_id,
        ScanRun.task.has(user_id=current_user.id)
    ).first_or_404()
    
    # Get the report
    report = ScanReport.query.filter_by(scan_run_id=scan_run.id).first_or_404()
    
    # Get host findings
    hosts = HostFinding.query.filter_by(report_id=report.id).all()
    
    # Build summary data
    summary_data = {
        'total_hosts': len(hosts),
        'hosts_up': sum(1 for h in hosts if h.status == 'up'),
        'hosts_down': sum(1 for h in hosts if h.status == 'down'),
        'total_open_ports': sum(PortFinding.query.filter(
            PortFinding.host_id == h.id,
            PortFinding.state == 'open'
        ).count() for h in hosts)
    }
    
    return jsonify(summary_data)

@reports_bp.route('/<int:run_id>/pdf')
@login_required
def report_pdf(run_id):
    if not WEASYPRINT_AVAILABLE:
        flash('PDF export is not available. Please install the required system dependencies.', 'warning')
        return redirect(url_for('reports.view', run_id=run_id))
        
    # Get the scan run and ensure it belongs to the current user
    scan_run = ScanRun.query.join(ScanRun.task).filter(
        ScanRun.id == run_id,
        ScanRun.task.has(user_id=current_user.id)
    ).first_or_404()
    
    # Get the report
    report = ScanReport.query.filter_by(scan_run_id=scan_run.id).first_or_404()
    
    # Parse summary if it exists
    summary = None
    if report.summary:
        try:
            summary = json.loads(report.summary)
        except json.JSONDecodeError:
            summary = None
    
    # Get all hosts and their ports
    host_data = []
    hosts = HostFinding.query.filter_by(report_id=report.id).all()
    for host in hosts:
        # Get port findings for this host
        ports = PortFinding.query.filter_by(host_id=host.id).order_by(PortFinding.port_number).all()
        
        # Parse OS info if it exists
        os_info = None
        if host.os_info:
            try:
                os_info = json.loads(host.os_info)
            except json.JSONDecodeError:
                os_info = None
        
        host_data.append({
            'host': host,
            'ports': ports,
            'os_info': os_info
        })
    
    # Render the template to HTML
    html_content = render_template(
        'reports/report_pdf.html',
        title=f'Scan Report: {scan_run.task.name}',
        scan_run=scan_run,
        report=report,
        summary=summary,
        host_data=host_data
    )
    
    # Create a PDF from the HTML content
    pdf_file = BytesIO()
    HTML(string=html_content).write_pdf(pdf_file)
    pdf_file.seek(0)
    
    # Create a response with the PDF
    # Sanitize task name for the filename (replace spaces with underscores and remove special characters)
    sanitized_task_name = ''.join(c if c.isalnum() else '_' for c in scan_run.task.name).strip('_')
    filename = f"scan_report_{sanitized_task_name}_{run_id}_UTC.pdf"
    return send_file(
        pdf_file,
        download_name=filename,
        as_attachment=True,
        mimetype='application/pdf'
    )

@reports_bp.route('/<int:run_id>/host/<int:host_id>/pdf')
@login_required
def host_pdf(run_id, host_id):
    if not WEASYPRINT_AVAILABLE:
        flash('PDF export is not available. Please install the required system dependencies.', 'warning')
        return redirect(url_for('reports.view_host', run_id=run_id, host_id=host_id))
        
    # Get the scan run and ensure it belongs to the current user
    scan_run = ScanRun.query.get_or_404(run_id)
    host = HostFinding.query.get_or_404(host_id)
    
    # Ensure the user has access to this scan run
    if scan_run.task.user_id != current_user.id:
        flash('You do not have permission to access this report.', 'danger')
        return redirect(url_for('main.index'))
    
    # Get all port findings for this host
    ports = PortFinding.query.filter_by(host_id=host_id).all()
    
    # Parse OS info if available
    os_info = None
    if host.os_info:
        try:
            os_info = json.loads(host.os_info)
        except json.JSONDecodeError:
            os_info = None
    
    # Render the HTML template
    html_content = render_template(
        'reports/host_pdf.html',
        host=host,
        ports=ports,
        scan_run=scan_run,
        os_info=os_info
    )
    
    # Generate PDF from HTML
    pdf_file = BytesIO()
    HTML(string=html_content).write_pdf(pdf_file)
    pdf_file.seek(0)
    
    # Create a response with the PDF
    # Sanitize task name for the filename (replace spaces with underscores and remove special characters)
    sanitized_task_name = ''.join(c if c.isalnum() else '_' for c in scan_run.task.name).strip('_')
    filename = f"host_report_{sanitized_task_name}_{host.ip_address}_{host.id}_UTC.pdf"
    return send_file(
        pdf_file,
        download_name=filename,
        as_attachment=True,
        mimetype='application/pdf'
    )
