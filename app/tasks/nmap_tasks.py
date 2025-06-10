import os
import json
import time
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
import signal
import atexit
from app import db
from app.models.task import ScanRun
from app.models.report import ScanReport, HostFinding, PortFinding
from flask import current_app
import nmap
from app.utils.sanitize import sanitize_nmap_command, sanitize_nmap_targets
from app.utils.validators import validate_nmap_args
from app.utils.decorators import sqlite_task_lock

@sqlite_task_lock(key_template="lock:run_nmap_scan:task_id_{scan_task_id_for_lock}", expire=43200) # 12 hours expire
def run_nmap_scan(scan_run_id, scan_task_id_for_lock):
    """
    Run an Nmap scan as a background Celery task.
    scan_task_id_for_lock is the ID of the parent ScanTask, used for locking to prevent concurrent runs of the same conceptual task.
    """
    # The on_task_exit function (formerly for Celery) is no longer needed.
    # This function should run within an existing app context provided by the scheduler.
    with current_app.app_context():
        # Get the scan run from the database
        scan_run = ScanRun.query.get(scan_run_id)
        if not scan_run:
            current_app.logger.error(f"[ScanRun {scan_run_id}] Scan run {scan_run_id} not found during task execution.")
            return
    
        # Update scan run status to 'starting'
        scan_run.status = 'starting'
        scan_run.started_at = datetime.utcnow()
        db.session.commit() # Moved inside the context
    
    try:
        # Variables to store data outside the app context
        targets = []
        scan_profile = None
        custom_args = None
        
        with current_app.app_context():
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
                message = "No targets specified"
                current_app.logger.error(f"[ScanRun {scan_run_id}] {message} for scan_run_id: {scan_run_id}")
                scan_run.error_message = message
                db.session.commit()
                return
        
        # Create a unique identifier for this scan
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        scan_id = f"scan_{scan_run_id}_{timestamp}"
        
        # Get the reports directory and prepare output paths
        with current_app.app_context():
            reports_dir = current_app.config['NMAP_REPORTS_DIR']
            nmap_profiles = current_app.config['NMAP_SCAN_PROFILES']
        
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
            current_app.logger.error(f"[ScanRun {scan_run_id}] Error initializing Nmap scanner: {str(e)}")
            with app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
            message = f'Error initializing Nmap scanner for scan_run_id {scan_run_id}: {str(e)}'
            current_app.logger.error(message)
            scan_run.error_message = message
            db.session.commit()
            return
        
        # Start the scan as a subprocess to capture real-time output
        # Use the full path to nmap
        nmap_path = "/usr/bin/nmap"
        
        # Sanitize the Nmap arguments to prevent command injection
        sanitized_nmap_args = sanitize_nmap_command(nmap_args)
        if sanitized_nmap_args is None:
            current_app.logger.error(f"[ScanRun {scan_run_id}] Error: Invalid or potentially dangerous Nmap arguments detected: {nmap_args}")
            with app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
            message = f"Invalid or potentially dangerous Nmap arguments detected for scan_run_id {scan_run_id}: {nmap_args}"
            current_app.logger.error(message)
            scan_run.error_message = message
            db.session.commit()
            return
        
        # Update the scan task with sanitized arguments if they've changed
        if sanitized_nmap_args != nmap_args:
            current_app.logger.info(f"[ScanRun {scan_run_id}] Sanitized Nmap arguments from '{nmap_args}' to '{sanitized_nmap_args}'")
            nmap_args = sanitized_nmap_args
            with current_app.app_context():
                scan_task.custom_args = sanitized_nmap_args
                db.session.commit()
        
        # Sanitize target string to prevent command injection
        sanitized_targets = []
        for target in target_string.split():
            sanitized_target = sanitize_nmap_targets(target)
            if sanitized_target:
                sanitized_targets.extend(sanitized_target)
        
        if not sanitized_targets:
            current_app.logger.error(f"[ScanRun {scan_run_id}] Error: No valid targets found in '{target_string}'")
            with current_app.app_context():
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
                current_app.logger.info(f"[ScanRun {scan_run_id}] Detected flag {flag} that requires root privileges")
                break
                
        # Also check for OS detection in other formats (case insensitive)
        if '--osscan-guess' in nmap_args.lower() or '--osscan-limit' in nmap_args.lower():
            requires_root = True
            current_app.logger.info(f"[ScanRun {scan_run_id}] Detected OS scan option that requires root privileges")
        
        # Always use sudo for OS detection and other privileged operations
        # This ensures we don't have to restart the scan later
        if requires_root:
            # Use sudo with NOPASSWD configuration
            sudo_prefix = "sudo "
            current_app.logger.info(f"[ScanRun {scan_run_id}] Detected operation requiring root privileges")
            current_app.logger.info(f"[ScanRun {scan_run_id}] Using sudo for privileged operations (NOPASSWD configured)")
        else:
            sudo_prefix = ""
        
        # Add -v for verbose output to make it easier to track progress
        cmd = f"{sudo_prefix}{nmap_path} -v {nmap_args} {sanitized_target_string}"
        
        try:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            # Store the process PID in the database
            with current_app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                if scan_run:
                    # Update status from 'starting' to 'running' now that the nmap process has started
                    scan_run.status = 'running'
                    scan_run.nmap_pid = process.pid
                    current_app.logger.info(f"[ScanRun {scan_run_id}] Attempting to commit PID {process.pid} and status 'running'.")
                    db.session.commit()
                    current_app.logger.info(f"[ScanRun {scan_run_id}] Successfully committed PID {process.pid} and status 'running'.")
        except Exception as e:
            current_app.logger.error(f"[ScanRun {scan_run_id}] Error starting Nmap process: {str(e)}")
            with current_app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                if scan_run: # Ensure scan_run object exists
                    scan_run.status = 'failed'
                    scan_run.completed_at = datetime.utcnow()
                    scan_run.error_message = str(e) # Store the error message
                    db.session.commit()
                else:
                    current_app.logger.error(f"[ScanRun {scan_run_id}] Scan run not found when trying to log Nmap process start error.")
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
                current_app.logger.error(f"[ScanRun {scan_run_id}] DETECTED PRIVILEGE ERROR: Restarting scan with sudo...")
                current_app.logger.error(f"[ScanRun {scan_run_id}] Error context: {last_error_line}")
                
                # Kill the current process
                process.terminate()
                process.wait(timeout=5)
                
                # Restart with sudo (using NOPASSWD configuration)
                cmd = f"sudo {nmap_path} -v {nmap_args} {target_string}"
                current_app.logger.info(f"[ScanRun {scan_run_id}] Restarting with sudo (NOPASSWD): {cmd}")
                
                try:
                    process = subprocess.Popen(
                        cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True
                    )
                    
                    # Update the stored PID and reset status
                    with current_app.app_context():
                        scan_run = ScanRun.query.get(scan_run_id)
                        if scan_run:
                            scan_run.nmap_pid = process.pid
                            # Ensure status is set to running in case it was changed
                            scan_run.status = 'running'
                            current_app.logger.info(f"[ScanRun {scan_run_id}] (Sudo Restart) Attempting to commit new PID {process.pid} and status 'running'.")
                            db.session.commit()
                            current_app.logger.info(f"[ScanRun {scan_run_id}] (Sudo Restart) Successfully committed new PID {process.pid} and status 'running'.")
                    
                    # Reset error tracking for the new process
                    privilege_error_detected = False
                    quitting_detected = False
                    last_error_line = ""
                    output_buffer = []
                    continue
                except Exception as e:
                    current_app.logger.error(f"[ScanRun {scan_run_id}] Error restarting with sudo: {str(e)}")
                    with current_app.app_context():
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
                    with current_app.app_context():
                        scan_run = ScanRun.query.get(scan_run_id)
                        if scan_run:
                            scan_run.progress = progress
                            db.session.commit()
                except Exception as e:
                    current_app.logger.error(f"[ScanRun {scan_run_id}] Error parsing progress: {str(e)}")
            
            # Check for scan completion
            if 'Nmap done' in line: 
                current_app.logger.info(f"[ScanRun {scan_run_id}] Scan completed successfully!")
                with current_app.app_context():
                    scan_run = ScanRun.query.get(scan_run_id)
                    scan_run.status = 'completed'
                    db.session.commit()
        
        # Process has completed
        return_code = process.poll()
        
        # Process tracking is now handled by the database PID and external cleanup scripts.
        
        # Check if there was any output at all
        if not output_buffer:
            current_app.logger.error(f"[ScanRun {scan_run_id}] No output received from Nmap process")
            with current_app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                if scan_run:
                    scan_run.status = 'failed'
                    scan_run.error_message = 'No output received from Nmap process'
                    scan_run.completed_at = datetime.utcnow()
                    db.session.commit()
            return # Task failed

        # Determine if Nmap considers itself done by checking the entire output buffer
        nmap_truly_done_in_output = any("Nmap done" in l for l in output_buffer)

        if return_code == 0 and nmap_truly_done_in_output:
            current_app.logger.info(f"[ScanRun {scan_run_id}] Nmap process completed successfully (return_code 0, 'Nmap done' found). Attempting to create report.")
            
            # xml_output and normal_output are defined earlier in this function
            if not os.path.exists(xml_output):
                current_app.logger.error(f"[ScanRun {scan_run_id}] XML output file {xml_output} not found after successful Nmap run.")
                with current_app.app_context():
                    scan_run = ScanRun.query.get(scan_run_id)
                    if scan_run:
                        scan_run.status = 'failed'
                        scan_run.error_message = f"Nmap completed but XML output file missing: {os.path.basename(xml_output)}"
                        scan_run.completed_at = datetime.utcnow()
                        db.session.commit()
            else:
                # Call create_scan_report. 
                new_report = create_scan_report(scan_run_id, xml_output, normal_output) # Removed current_app, as create_scan_report was refactored
                
                with current_app.app_context(): # Ensure app context for DB operations
                    scan_run = ScanRun.query.get(scan_run_id) # Re-fetch for current session
                    if scan_run:
                        if new_report:
                            current_app.logger.info(f"[ScanRun {scan_run_id}] Report created successfully (Report ID: {new_report.id}).")
                            scan_run.status = 'completed'
                            scan_run.report = new_report # Link the report object
                            scan_run.error_message = None # Clear any previous error
                        else:
                            current_app.logger.error(f"[ScanRun {scan_run_id}] Failed to create report from Nmap output.")
                            scan_run.status = 'failed'
                            scan_run.error_message = "Report creation failed after Nmap scan."
                        scan_run.completed_at = datetime.utcnow()
                        db.session.commit()
                    else:
                        current_app.logger.error(f"[ScanRun {scan_run_id}] ScanRun object not found when trying to finalize after report creation attempt.")

        elif return_code != 0:
            current_app.logger.error(f"[ScanRun {scan_run_id}] Nmap process exited with non-zero return code: {return_code}.")
            detailed_error_message = f"Nmap process failed with return code {return_code}."
            
            # Try to find a more specific error message from output_buffer
            extracted_nmap_error = None
            for i, l_item in enumerate(output_buffer):
                if 'QUITTING!' in l_item:
                    if i > 0:
                        extracted_nmap_error = output_buffer[i-1].strip()
                    else:
                        extracted_nmap_error = "Nmap quit unexpectedly (QUITTING! found at start of output)."
                    break # Found the primary error indicator
            
            if extracted_nmap_error:
                detailed_error_message = extracted_nmap_error
            elif output_buffer: # If no QUITTING msg, use last few lines as potential error context
                context_lines = "\n".join(output_buffer[-5:])
                detailed_error_message += f"\nLast output lines:\n{context_lines}"

            with current_app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                if scan_run:
                    scan_run.status = 'failed'
                    scan_run.error_message = str(detailed_error_message)[:1023] # Ensure fits in DB
                    scan_run.completed_at = datetime.utcnow()
                    db.session.commit()
                else:
                    current_app.logger.error(f"[ScanRun {scan_run_id}] ScanRun object not found when handling Nmap process failure (return_code {return_code}).")

        else: # return_code == 0 but not nmap_truly_done_in_output
            current_app.logger.warning(f"[ScanRun {scan_run_id}] Nmap process finished with return_code 0, but 'Nmap done' was not found in output. Scan may be incomplete or output corrupted.")
            with current_app.app_context():
                scan_run = ScanRun.query.get(scan_run_id)
                if scan_run:
                    scan_run.status = 'failed'
                    scan_run.error_message = "Nmap finished (code 0) but output indicates incompletion or error (no 'Nmap done' marker)."
                    scan_run.completed_at = datetime.utcnow()
                    db.session.commit()
                else:
                    current_app.logger.error(f"[ScanRun {scan_run_id}] ScanRun object not found when handling incomplete Nmap scan (code 0, no 'Nmap done').")
            
    except Exception as e:
        current_app.logger.error(f"[ScanRun {scan_run_id}] Unhandled exception in run_nmap_scan: {str(e)}", exc_info=True)
        with current_app.app_context():
            scan_run = ScanRun.query.get(scan_run_id)
            if scan_run:
                scan_run.status = 'failed'
                scan_run.completed_at = datetime.utcnow()
                db.session.commit()
        return {'status': 'failed', 'message': str(e), 'scan_run_id': scan_run_id}

def create_scan_report(scan_run_id, xml_path, normal_path):
    """
    Parse Nmap XML output and create a report in the database
    Also enforces the maximum reports per task setting by deleting older reports
    """
    parsed_summary = {}
    parsed_hosts_data = []

    try:
        if not os.path.exists(xml_path):
            current_app.logger.error(f"[ScanRun {scan_run_id}] Nmap XML output file not found: {xml_path}")
            return None
        tree = ET.parse(xml_path)
        root = tree.getroot()

        # Extract summary information
        parsed_summary = {
            'scanner': root.get('scanner', ''),
            'args': root.get('args', ''),
            'start': root.get('start', ''),
            'startstr': root.get('startstr', ''),
            'version': root.get('version', ''),
            'xmloutputversion': root.get('xmloutputversion', '')
        }
        run_stats = root.find('runstats')
        if run_stats is not None:
            hosts_stats = run_stats.find('hosts')
            if hosts_stats is not None:
                parsed_summary['hosts_total'] = hosts_stats.get('total', '0')
                parsed_summary['hosts_up'] = hosts_stats.get('up', '0')
                parsed_summary['hosts_down'] = hosts_stats.get('down', '0')

        # Process each host from XML
        for host_elem in root.findall('host'):
            host_data = {}
            status_elem = host_elem.find('status')
            host_data['status'] = status_elem.get('state') if status_elem is not None else 'unknown'
            address_elem = host_elem.find('address')
            host_data['ip_address'] = address_elem.get('addr') if address_elem is not None else ''
            
            hostnames_elem = host_elem.find('hostnames')
            hostname = None
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')
            host_data['hostname'] = hostname

            os_info_parts = []
            os_elem = host_elem.find('os')
            if os_elem is not None:
                for osmatch_elem in os_elem.findall('osmatch'):
                    os_name = osmatch_elem.get('name', 'Unknown OS')
                    os_accuracy = osmatch_elem.get('accuracy', '0')
                    os_info_parts.append(f"{os_name} (Accuracy: {os_accuracy}%)")
                    for osclass_elem in osmatch_elem.findall('osclass'):
                        os_vendor = osclass_elem.get('vendor', '')
                        os_family = osclass_elem.get('osfamily', '')
                        os_gen = osclass_elem.get('osgen', '')
                        os_class_type = osclass_elem.get('type', '')
                        os_info_parts.append(f"  Class: {os_class_type} | Vendor: {os_vendor} | Family: {os_family} | Gen: {os_gen}")
            host_data['os_info'] = json.dumps(os_info_parts) if os_info_parts else None
            
            host_data['ports'] = []
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_data = {}
                    port_data['port_number'] = port_elem.get('portid')
                    port_data['protocol'] = port_elem.get('protocol')
                    state_elem = port_elem.find('state')
                    port_data['state'] = state_elem.get('state') if state_elem is not None else 'unknown'
                    
                    service_elem = port_elem.find('service')
                    service_name = ''
                    service_version = ''
                    if service_elem is not None:
                        service_parts = [
                            service_elem.get('name', ''),
                            service_elem.get('product', ''),
                            service_elem.get('extrainfo', '')
                        ]
                        service_name = ' '.join(filter(None, service_parts)).strip()
                        service_version = service_elem.get('version')
                    port_data['service'] = service_name
                    port_data['version'] = service_version
                    host_data['ports'].append(port_data)
            parsed_hosts_data.append(host_data)

    except Exception as e:
        current_app.logger.error(f"[ScanRun {scan_run_id}] Error during XML parsing phase: {str(e)}", exc_info=True)
        return None

    # Database transaction part
    try:
        with current_app.app_context():
            scan_run = ScanRun.query.get(scan_run_id)
            if not scan_run:
                current_app.logger.error(f"[ScanRun {scan_run_id}] Scan run {scan_run_id} not found before DB operations.")
                return None
            scan_task = scan_run.task

            if scan_task.use_global_max_reports:
                from app.models.settings import SystemSettings
                max_reports = SystemSettings.get_int('max_reports_per_task', 15)
            else:
                max_reports = scan_task.max_reports or 15

            # Create new ScanReport object
            new_report = ScanReport(
                scan_run_id=scan_run_id,
                xml_report_path=xml_path,
                normal_report_path=normal_path,
                summary=json.dumps(parsed_summary)
            )

            # Create HostFinding and PortFinding objects from parsed data
            for host_data in parsed_hosts_data:
                host_finding = HostFinding(
                    ip_address=host_data['ip_address'],
                    hostname=host_data['hostname'],
                    status=host_data['status'],
                    os_info=host_data['os_info']
                    # report_id will be set by relationship
                )
                for port_data in host_data['ports']:
                    port_finding = PortFinding(
                        port_number=int(port_data['port_number']),
                        protocol=port_data['protocol'],
                        state=port_data['state'],
                        service=port_data['service'],
                        version=port_data['version']
                        # host_id will be set by relationship
                    )
                    host_finding.ports.append(port_finding)
                new_report.hosts.append(host_finding)
            
            db.session.add(new_report)

            # Cleanup old reports - Query needs to be effective *after* the new report is conceptually part of the task's reports
            # To do this safely, we might need to flush to get the new_report an ID if the query relies on it, 
            # or adjust the query. For now, let's assume the query for task_reports correctly includes the pending new_report.
            # A safer way is to commit the new report first, then cleanup. But let's try with current structure.
            # If issues persist, this part may need adjustment (e.g. commit new_report, then query and delete old ones in a new transaction or step).
            
            # Get all reports for this task, ordered by creation date (newest first)
            # We need to ensure 'new_report' is considered in this list if it's already added to session
            # A flush might be needed here if the query doesn't see 'new_report' yet.
            db.session.flush() # Ensure new_report gets an ID and is queryable if needed by relationships in task_reports query

            task_reports = ScanReport.query.join(ScanRun).filter(
                ScanRun.task_id == scan_task.id
            ).order_by(ScanReport.created_at.desc(), ScanReport.id.desc()).all()
            
            if len(task_reports) > max_reports:
                reports_to_delete = task_reports[max_reports:] # Oldest reports are at the end
                current_app.logger.info(f"[ScanRun {scan_run_id}] Cleaning up {len(reports_to_delete)} old reports for task {scan_task.id} to maintain max of {max_reports}")
                for old_report_to_delete in reports_to_delete:
                    if old_report_to_delete.id == new_report.id: # Should not happen if ordering is correct and new_report is fresh
                        current_app.logger.warning(f"[ScanRun {scan_run_id}] Attempted to delete the new report (ID: {new_report.id}) during cleanup. Skipping.")
                        continue
                    
                    if old_report_to_delete.xml_report_path and os.path.exists(old_report_to_delete.xml_report_path):
                        try: os.remove(old_report_to_delete.xml_report_path)
                        except Exception as e: current_app.logger.error(f"[ScanRun {scan_run_id}] Error deleting XML file {old_report_to_delete.xml_report_path}: {str(e)}")
                    if old_report_to_delete.normal_report_path and os.path.exists(old_report_to_delete.normal_report_path):
                        try: os.remove(old_report_to_delete.normal_report_path)
                        except Exception as e: current_app.logger.error(f"[ScanRun {scan_run_id}] Error deleting normal file {old_report_to_delete.normal_report_path}: {str(e)}")
                    db.session.delete(old_report_to_delete)
            
            db.session.commit()
            current_app.logger.info(f"[ScanRun {scan_run_id}] Scan report created successfully. Report ID: {new_report.id}")
            return new_report

    except Exception as e:
        # This will catch errors from the database transaction part or if app_context fails
        with current_app.app_context(): # Ensure context for rollback if error was in DB part
            db.session.rollback()
        current_app.logger.error(f"[ScanRun {scan_run_id}] Error in create_scan_report DB phase: {str(e)}", exc_info=True)
        return None
