import os
import json
import time
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
import signal
import atexit
from celery import shared_task, states
from celery.signals import task_failure, task_success, task_revoked
from celery_config import celery
from app import db
from app.models.task import ScanRun
from app.models.report import ScanReport, HostFinding, PortFinding
from flask import current_app
import nmap
from app.utils.sanitize import sanitize_nmap_command, sanitize_nmap_targets
from app.utils.validators import validate_nmap_args

# Global dictionary to track active processes
active_processes = {}

# Signal handler for task cleanup
def cleanup_task(scan_run_id, process=None):
    """Ensure task is properly cleaned up"""
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            scan_run = ScanRun.query.get(scan_run_id)
            if scan_run and scan_run.status == 'running':
                print(f"Cleaning up task for scan run {scan_run_id}")
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
                print(f"Updated scan run {scan_run_id} status to failed")
            
            # Kill the process if it's still running
            if process and process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=3)
                except:
                    try:
                        process.kill()
                    except:
                        pass
        except Exception as e:
            print(f"Error in cleanup_task: {str(e)}")
    
    # Remove from active processes
    if scan_run_id in active_processes:
        del active_processes[scan_run_id]

# Register Celery signal handlers
@task_failure.connect
def handle_task_failure(sender=None, task_id=None, exception=None, args=None, **kwargs):
    """Handle task failure signal"""
    if args and len(args) > 0:
        scan_run_id = args[0]
        print(f"Task failure detected for scan run {scan_run_id}")
        if scan_run_id in active_processes:
            cleanup_task(scan_run_id, active_processes[scan_run_id])

@task_success.connect
def handle_task_success(sender=None, result=None, **kwargs):
    """Handle task success signal"""
    # Check if the result indicates a failure
    if isinstance(result, dict) and result.get('status') == 'failed':
        if 'scan_run_id' in sender.request.kwargs:
            scan_run_id = sender.request.kwargs['scan_run_id']
            print(f"Task reported failure for scan run {scan_run_id}")
            if scan_run_id in active_processes:
                cleanup_task(scan_run_id, active_processes[scan_run_id])

@task_revoked.connect
def handle_task_revoked(sender=None, request=None, **kwargs):
    """Handle task revoked signal"""
    if request and request.args and len(request.args) > 0:
        scan_run_id = request.args[0]
        print(f"Task revoked for scan run {scan_run_id}")
        if scan_run_id in active_processes:
            cleanup_task(scan_run_id, active_processes[scan_run_id])

# Register exit handler
def exit_handler():
    """Clean up any remaining tasks on exit"""
    for scan_run_id, process in active_processes.items():
        print(f"Cleaning up task for scan run {scan_run_id} on exit")
        cleanup_task(scan_run_id, process)

atexit.register(exit_handler)

@shared_task(bind=True)
def run_nmap_scan(self, scan_run_id):
    """
    Run an Nmap scan as a background Celery task
    """
    # Import Flask app and create application context
    from app import create_app
    app = create_app()
    
    # Register a task-specific cleanup function
    def on_task_exit(scan_run_id=scan_run_id):
        print(f"Task exit handler for scan run {scan_run_id}")
        if scan_run_id in active_processes:
            cleanup_task(scan_run_id, active_processes[scan_run_id])
    
    # Register the cleanup function for this task
    self.request.on_timeout = lambda: on_task_exit()
    
    with app.app_context():
        # Get the scan run from the database
        scan_run = ScanRun.query.get(scan_run_id)
        if not scan_run:
            return {'status': 'failed', 'message': 'Scan run not found'}
    
        # Update scan run status
        scan_run.status = 'running'
        scan_run.celery_task_id = self.request.id
        scan_run.started_at = datetime.utcnow()
        db.session.commit()
    
    try:
        # Variables to store data outside the app context
        targets = []
        scan_profile = None
        custom_args = None
        
        with app.app_context():
            # Get the scan task and target groups - need to refresh the scan_run object
            scan_run = ScanRun.query.get(scan_run_id)
            scan_task = scan_run.task
            
            # Store the scan profile and custom args for later use
            scan_profile = scan_task.scan_profile
            custom_args = scan_task.custom_args
            
            # Get all target groups and their targets
            for group in scan_task.target_groups:
                for target in group.targets:
                    targets.append(target.value)
            
            if not targets:
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
                return {'status': 'failed', 'message': 'No targets specified'}
        
        # Create a unique identifier for this scan
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        scan_id = f"scan_{scan_run_id}_{timestamp}"
        
        # Get the reports directory and prepare output paths
        with app.app_context():
            reports_dir = app.config['NMAP_REPORTS_DIR']
            nmap_profiles = app.config['NMAP_SCAN_PROFILES']
        
        # Ensure reports directory exists
        os.makedirs(reports_dir, exist_ok=True)
        
        # Prepare output file paths
        xml_output = os.path.join(reports_dir, f"{scan_id}.xml")
        normal_output = os.path.join(reports_dir, f"{scan_id}.txt")
        
        # Prepare Nmap arguments
        if scan_profile and scan_profile in nmap_profiles:
            nmap_args = nmap_profiles[scan_profile]
        elif custom_args:
            nmap_args = custom_args
        else:
            nmap_args = '-T4 -F'  # Default to quick scan
        
        # Add output formats to arguments
        nmap_args += f" -oX {xml_output} -oN {normal_output}"
        
        # Add stats for progress tracking
        nmap_args += " --stats-every 5s"
        
        # Create target string
        target_string = ' '.join(targets)
        
        # Initialize nmap scanner
        try:
            nm = nmap.PortScanner()
        except Exception as e:
            print(f"Error initializing Nmap scanner: {str(e)}")
            with app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
            return {'status': 'failed', 'message': f'Error initializing Nmap scanner: {str(e)}'}
        
        # Start the scan as a subprocess to capture real-time output
        # Use the full path to nmap
        nmap_path = "/usr/bin/nmap"
        
        # Sanitize the Nmap arguments to prevent command injection
        sanitized_nmap_args = sanitize_nmap_command(nmap_args)
        if sanitized_nmap_args is None:
            print(f"Error: Invalid or potentially dangerous Nmap arguments detected: {nmap_args}")
            with app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
            return {'status': 'failed', 'message': 'Invalid or potentially dangerous Nmap arguments detected'}
        
        # Update the scan task with sanitized arguments if they've changed
        if sanitized_nmap_args != nmap_args:
            print(f"Sanitized Nmap arguments from '{nmap_args}' to '{sanitized_nmap_args}'")
            nmap_args = sanitized_nmap_args
            with app.app_context():
                scan_task.custom_args = sanitized_nmap_args
                db.session.commit()
        
        # Sanitize target string to prevent command injection
        sanitized_targets = []
        for target in target_string.split():
            sanitized_target = sanitize_nmap_targets(target)
            if sanitized_target:
                sanitized_targets.extend(sanitized_target)
        
        if not sanitized_targets:
            print(f"Error: No valid targets found in '{target_string}'")
            with app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
            return {'status': 'failed', 'message': 'No valid targets found'}
        
        # Join the sanitized targets back into a string
        sanitized_target_string = ' '.join(sanitized_targets)
        
        # Check if the scan requires root privileges
        requires_root = False
        
        # OS detection (-O), SYN scan (-sS), and some other scan types require root
        # Check for both space-separated flags and combined flags
        root_flags = ['-O', '-sS', '-sU', '-sA', '-sW', '-sM']
        
        # Check each flag individually to ensure we catch them regardless of format
        for flag in root_flags:
            if flag in nmap_args.split() or flag in nmap_args:
                requires_root = True
                print(f"Detected flag {flag} that requires root privileges")
                break
                
        # Also check for OS detection in other formats (case insensitive)
        if '--osscan-guess' in nmap_args.lower() or '--osscan-limit' in nmap_args.lower():
            requires_root = True
            print("Detected OS scan option that requires root privileges")
        
        # Always use sudo for OS detection and other privileged operations
        # This ensures we don't have to restart the scan later
        if requires_root:
            # Use sudo with NOPASSWD configuration
            sudo_prefix = "sudo "
            print("Detected operation requiring root privileges")
            print("Using sudo for privileged operations (NOPASSWD configured)")
        else:
            sudo_prefix = ""
        
        # Add -v for verbose output to make it easier to track progress
        cmd = f"{sudo_prefix}{nmap_path} -v {nmap_args} {sanitized_target_string}"
        print(f"Executing Nmap command: {cmd}")
        
        # Add a sleep to make it easier to catch the process with ps
        print("Sleeping for 5 seconds before starting Nmap...")
        time.sleep(5)
        print("Starting Nmap scan now...")
        
        # Check if the Nmap executable exists
        if not os.path.exists(nmap_path):
            print(f"Error: Nmap executable not found at {nmap_path}")
            with app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
            return {'status': 'failed', 'message': f'Nmap executable not found at {nmap_path}'}
        
        try:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            # Store the process in our tracking dictionary
            active_processes[scan_run_id] = process
            
            # Store the process PID in the database
            with app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                if scan_run:
                    scan_run.nmap_pid = process.pid
                    db.session.commit()
                    print(f"Stored nmap PID {process.pid} for scan run {scan_run_id}")
        except Exception as e:
            print(f"Error starting Nmap process: {str(e)}")
            with app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
            return {'status': 'failed', 'message': f'Error starting Nmap process: {str(e)}'}
        
        # Variables to track process state and errors
        privilege_error_detected = False
        quitting_detected = False
        last_error_line = ""
        output_buffer = []
        
        # Monitor progress
        while process.poll() is None:
            # Read output line by line
            output = process.stdout.readline()
            if not output:
                continue
                
            line = output.strip()
            print(f"Nmap output: {line}")
            
            # Store recent output lines for context
            output_buffer.append(line)
            if len(output_buffer) > 10:  # Keep last 10 lines
                output_buffer.pop(0)
            
            # Check for errors requiring root privileges
            privilege_error = False
            
            # Look for common privilege error messages
            if any(msg in line for msg in [
                'requires root privileges',
                'requires privileged access',
                'TCP/IP fingerprinting (for OS scan) requires root privileges'
            ]):
                privilege_error = True
                privilege_error_detected = True
                last_error_line = line
            
            # Check for QUITTING message
            if 'QUITTING!' in line:
                quitting_detected = True
                
                # If we've seen a privilege error before QUITTING, it's definitely a privilege issue
                if privilege_error_detected:
                    privilege_error = True
                
                # Also check if any recent output lines contain privilege errors
                for recent_line in output_buffer:
                    if any(msg in recent_line for msg in [
                        'root privileges', 'privileged access', 'TCP/IP fingerprinting'
                    ]):
                        privilege_error = True
                        break
                
            if privilege_error:
                print("\n" + "=" * 80)
                print("DETECTED PRIVILEGE ERROR: Restarting scan with sudo...")
                print(f"Error context: {last_error_line}")
                print("=" * 80 + "\n")
                
                # Kill the current process and remove from tracking
                process.terminate()
                process.wait(timeout=5)
                if scan_run_id in active_processes:
                    del active_processes[scan_run_id]
                
                # Restart with sudo (using NOPASSWD configuration)
                cmd = f"sudo {nmap_path} -v {nmap_args} {target_string}"
                print(f"Restarting with sudo (NOPASSWD): {cmd}")
                
                try:
                    process = subprocess.Popen(
                        cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True
                    )
                    
                    # Store the new process in our tracking dictionary
                    active_processes[scan_run_id] = process
                    
                    # Update the stored PID and reset status
                    with app.app_context():
                        scan_run = ScanRun.query.get(scan_run_id)
                        if scan_run:
                            scan_run.nmap_pid = process.pid
                            # Ensure status is set to running in case it was changed
                            scan_run.status = 'running'
                            db.session.commit()
                            print(f"Updated nmap PID to {process.pid} for scan run {scan_run_id}")
                    
                    # Reset error tracking for the new process
                    privilege_error_detected = False
                    quitting_detected = False
                    last_error_line = ""
                    output_buffer = []
                    continue
                except Exception as e:
                    print(f"Error restarting with sudo: {str(e)}")
                    with app.app_context():
                        scan_run = ScanRun.query.get(scan_run_id)
                        scan_run.status = 'failed'
                        scan_run.completed_at = datetime.utcnow()
                        db.session.commit()
                    return {'status': 'failed', 'message': f'Error restarting with sudo: {str(e)}'}
            
            # Check for progress updates
            if 'About' in line and '% done' in line:
                try:
                    # Extract progress percentage
                    progress_str = line.split('About ')[1].split('% done')[0].strip()
                    progress = int(float(progress_str))
                    
                    # Update progress in database
                    with app.app_context():
                        scan_run = ScanRun.query.get(scan_run_id)
                        if scan_run:
                            scan_run.progress = progress
                            db.session.commit()
                except Exception as e:
                    print(f"Error parsing progress: {str(e)}")
            
            # Check for scan completion
            if 'Nmap done' in line: 
                print("Scan completed successfully!")
                with app.app_context():
                    scan_run = ScanRun.query.get(scan_run_id)
                    scan_run.status = 'completed'
                    db.session.commit()
        
        # Process has completed
        return_code = process.poll()
        
        # Remove the process from our tracking dictionary
        if scan_run_id in active_processes:
            del active_processes[scan_run_id]
        
        # Check if there was any output at all
        if not output_buffer:
            print("No output received from Nmap process")
            with app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
            return {'status': 'failed', 'message': 'No output received from Nmap process', 'scan_run_id': scan_run_id}
        
        # Check for specific error conditions in the output buffer
        error_message = None
        for line in output_buffer:
            if 'QUITTING!' in line:
                # Find the line before QUITTING to get the error reason
                quitting_index = output_buffer.index(line)
                if quitting_index > 0:
                    error_message = output_buffer[quitting_index-1]
                break
        
        if return_code != 0:
            print(f"Nmap process exited with non-zero return code: {return_code}")
            with app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
                
            # Provide a more detailed error message if available
            if error_message:
                return {'status': 'failed', 'message': f'Nmap scan failed: {error_message} (return code {return_code})', 'scan_run_id': scan_run_id}
            else:
                return {'status': 'failed', 'message': f'Nmap scan failed with return code {return_code}', 'scan_run_id': scan_run_id}
        
        # Check if the XML output file exists
        if os.path.exists(xml_output):
            print(f"XML output file found at: {xml_output}")
            try:
                # Parse the XML output and create report
                # Store the process PID in the database
                with app.app_context():
                    scan_run = ScanRun.query.get(scan_run_id)
                    if scan_run:
                        scan_run.nmap_pid = process.pid
                        db.session.commit()
                        print(f"Stored nmap PID {process.pid} for scan run {scan_run_id}")
                
                # Start the scan
                for line in iter(process.stdout.readline, ''):
                    print(line.strip())
                    
                    # Update progress based on output
                    with app.app_context():
                        scan_run = ScanRun.query.get(scan_run_id)
                        if not scan_run:
                            break
                        scan_run.progress = 100
                        db.session.commit()
                    
                create_scan_report(app, scan_run_id, xml_output, normal_output)
                
                # Update scan run status
                with app.app_context():
                    scan_run = ScanRun.query.get(scan_run_id)
                    scan_run.status = 'completed'
                    scan_run.completed_at = datetime.utcnow()
                    scan_run.progress = 100
                    db.session.commit()
                
                return {
                    'status': 'completed',
                    'xml_output': xml_output,
                    'normal_output': normal_output
                }
            except Exception as e:
                print(f"Error creating scan report: {str(e)}")
                with app.app_context():
                    scan_run = ScanRun.query.get(scan_run_id)
                    scan_run.status = 'failed'
                    scan_run.completed_at = datetime.utcnow()
                    db.session.commit()
                return {'status': 'failed', 'message': f'Error creating scan report: {str(e)}'}
        else:
            print(f"XML output file not found at: {xml_output}")
            with app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
            return {'status': 'failed', 'message': 'Nmap scan did not produce output files'}
            
    except Exception as e:
        print(f"Error in run_nmap_scan: {str(e)}")
        # Remove the process from our tracking dictionary
        if scan_run_id in active_processes:
            del active_processes[scan_run_id]
            
        with app.app_context():
            scan_run = ScanRun.query.get(scan_run_id)
            if scan_run:
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
        return {'status': 'failed', 'message': str(e), 'scan_run_id': scan_run_id}

def create_scan_report(app, scan_run_id, xml_path, normal_path):
    """
    Parse Nmap XML output and create a report in the database
    Also enforces the maximum reports per task setting by deleting older reports
    """
    try:
        with app.app_context():
            # Get the scan run
            scan_run = ScanRun.query.get(scan_run_id)
            if not scan_run:
                print(f"Scan run {scan_run_id} not found")
                return None
            
            # Get the scan task to determine max reports setting
            scan_task = scan_run.task
            
            # Determine the maximum reports to keep
            if scan_task.use_global_max_reports:
                from app.models.settings import SystemSettings
                max_reports = SystemSettings.get_int('max_reports_per_task', 15)
            else:
                max_reports = scan_task.max_reports or 15
                
            # Create a new report
            report = ScanReport(
                scan_run_id=scan_run_id,
                xml_report_path=xml_path,
                normal_report_path=normal_path
            )
            db.session.add(report)
            db.session.flush()  # Get the report ID
            
            # Check if we need to clean up old reports
            # Get all reports for this task, ordered by creation date (newest first)
            task_reports = ScanReport.query.join(ScanRun).filter(
                ScanRun.task_id == scan_task.id
            ).order_by(ScanReport.created_at.desc()).all()
            
            # If we have more reports than the maximum allowed, delete the oldest ones
            if len(task_reports) > max_reports:
                reports_to_delete = task_reports[max_reports:]
                print(f"Cleaning up {len(reports_to_delete)} old reports for task {scan_task.id} to maintain max of {max_reports}")
                
                for old_report in reports_to_delete:
                    # Delete the report files from disk if they exist
                    if old_report.xml_report_path and os.path.exists(old_report.xml_report_path):
                        try:
                            os.remove(old_report.xml_report_path)
                        except Exception as e:
                            print(f"Error deleting XML report file {old_report.xml_report_path}: {str(e)}")
                    
                    if old_report.normal_report_path and os.path.exists(old_report.normal_report_path):
                        try:
                            os.remove(old_report.normal_report_path)
                        except Exception as e:
                            print(f"Error deleting normal report file {old_report.normal_report_path}: {str(e)}")
                    
                    # Delete the report from the database
                    db.session.delete(old_report)
            
            # Parse the XML file
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # Extract summary information
            summary = {
                'scanner': root.get('scanner', ''),
                'args': root.get('args', ''),
                'start': root.get('start', ''),
                'startstr': root.get('startstr', ''),
                'version': root.get('version', ''),
                'xmloutputversion': root.get('xmloutputversion', '')
            }
            
            # Get scan info
            run_stats = root.find('runstats')
            if run_stats is not None:
                hosts_stats = run_stats.find('hosts')
                if hosts_stats is not None:
                    summary['hosts_total'] = hosts_stats.get('total', '0')
                    summary['hosts_up'] = hosts_stats.get('up', '0')
                    summary['hosts_down'] = hosts_stats.get('down', '0')
            
            report.summary = json.dumps(summary)
        
            # Process each host
            for host_elem in root.findall('host'):
                # Get host status
                status = host_elem.find('status')
                host_status = status.get('state') if status is not None else 'unknown'
                
                # Get address
                address = host_elem.find('address')
                ip_address = address.get('addr') if address is not None else ''
                
                # Get hostname
                hostnames_elem = host_elem.find('hostnames')
                hostname = None
                if hostnames_elem is not None:
                    hostname_elem = hostnames_elem.find('hostname')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name')
                
                # Get OS information
                os_elem = host_elem.find('os')
                os_info = None
                if os_elem is not None:
                    os_match = os_elem.find('osmatch')
                    if os_match is not None:
                        os_info = {
                            'name': os_match.get('name', ''),
                            'accuracy': os_match.get('accuracy', '')
                        }
                
                # Create host finding
                host_finding = HostFinding(
                    report_id=report.id,
                    ip_address=ip_address,
                    hostname=hostname,
                    status=host_status,
                    os_info=json.dumps(os_info) if os_info else None
                )
                db.session.add(host_finding)
                db.session.flush()  # Get the host finding ID
            
                # Process ports
                ports_elem = host_elem.find('ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('port'):
                        port_number = port_elem.get('portid')
                        protocol = port_elem.get('protocol')
                        
                        # Get port state
                        state_elem = port_elem.find('state')
                        state = state_elem.get('state') if state_elem is not None else 'unknown'
                        
                        # Get service info
                        service_elem = port_elem.find('service')
                        service = None
                        version = None
                        if service_elem is not None:
                            service = service_elem.get('name')
                            product = service_elem.get('product', '')
                            version_str = service_elem.get('version', '')
                            extrainfo = service_elem.get('extrainfo', '')
                            version = ' '.join(filter(None, [product, version_str, extrainfo]))
                        
                        # Create port finding
                        port_finding = PortFinding(
                            host_id=host_finding.id,
                            port_number=port_number,
                            protocol=protocol,
                            state=state,
                            service=service,
                            version=version
                        )
                        db.session.add(port_finding)
        
            db.session.commit()
            return report
    
    except Exception as e:
        with app.app_context():
            db.session.rollback()
        print(f"Error parsing Nmap XML: {str(e)}")
        return None
