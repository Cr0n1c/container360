import subprocess

import docker 

from sqlalchemy.exc import IntegrityError
from database.models import ThreatModel

class MitreScan:

    def __init__(self, container, image_path, image_uuid, db) -> None:
        self.container = container
        self.image_path = image_path
        self.image_uuid = image_uuid
        self.db = db
        self.default_user_root = True if self.__run_container_process("whoami") == "root" else False
        self.package_manager_installed = True if self.__run_container_process("which apt-get") else False
        self.run_scan()

    def run_scan(self):
        self.__initial_assess()
        self.__execution()
        self.__persistence()
        self.__privilege_escalation()
        self.__defense_evasion()
        self.__credential_access()
        self.__discovery()
        self.__lateral_movement()
        self.__impact()

    def db_add(self, technique, event) -> bool:
        try:
            self.db.add(ThreatModel(image_uuid=self.image_uuid, technique=technique, event=event))
            self.db.commit()
        except IntegrityError:
            self.db.flush()
            self.db.rollback()
            return False
        else:
            return True

    def __run_container_process(self, process=str) -> bool:
        try:
            results = self.container.exec_run(cmd=process, demux=True, privileged=True, tty=True)
        except docker.errors.APIError as e:
            print(e)
            return False
        else:
            return results

    def __initial_assess(self) -> bool:
        # Valid Accounts: Unabled to programmatically determine at this moment.

        # Exploit Public-Facing Application	and External Remote Services	
        results = subprocess.check_output([
            'docker', 
            'history', 
            self.image_path, 
            '--format', 
            '"{{.ID}}|{{.CreatedSince}}|{{.CreatedAt}}|{{.CreatedBy}}|{{.Size}}|{{.Comment}}"', 
            '--no-trunc'
        ]).decode('utf-8').split('\n')

        for row in results:
            if row.lower().startswith("expose "):
                self.db_add("public-facing-application", f"Exposed port: {' '.join(row.split(' ')[1:])} allows potential attacker access.")
                self.db_add("external-remote-services", f"Exposed port: {' '.join(row.split(' ')[1:])} allows potential attacker access.")
        
        return True

    def __execution(self) -> bool:
        # Container Administration Command: Unabled to programmatically determine at this moment.
        # Deploy Container: Unabled to programmatically determine at this moment.
        # User Execution: Unabled to programmatically determine at this moment.

        # Scheduled Task/Job	
        results = self.__run_container_process("crontab -l |grep -v run-parts | grep -v ^#")
        if results:
            self.db_add("persistence", "Detected cron installed")
            self.db_add("privilege-escalation", "Detected cron installed")

        for row in results:
            self.db_add("scheduled-task", f"Detected cron job: {row}")

        if self.default_user_root:
            if self.__run_container_process("which crontab"):
                self.db_add("scheduled-task", "Default user 'root' can add cron jobs")
            elif self.package_manager_installed:
                self.db_add("scheduled-task", "Default user 'root' can install cron using 'apt-get' as it is installed")

        return True

    def __persistence(self) -> bool:
        # Implant Internal Image: Unabled to programmatically determine at this moment.
        # Valid Accounts: Unabled to programmatically determine at this moment.
        # Scheduled Task/Job: Logic is in __execution()
        # External Remote Services: Logic is in __initial_access()  
        return True

    def __privilege_escalation(self) -> bool:
        # Exploitation for Privilege Escalation: Unabled to programmatically determine at this moment.
        # Valid Accounts: Unabled to programmatically determine at this moment.
        # Escape to Host: Unabled to programmatically determine at this moment.
        # Scheduled Task/Job: Logic is in __execution()
        # Check if root is default user
        if self.default_user_root:
            self.db_add("privilege-escalation", "Default user is 'root', no need to escalate privileges")

        return True

    def __defense_evasion(self) -> bool:
        # Build Image on Host: Unabled to programmatically determine at this moment.
        # Deploy Container: Unabled to programmatically determine at this moment.
        # Use Alternate Authentication Material: Unabled to programmatically determine at this moment.
        # Valid Accounts: Unabled to programmatically determine at this moment.

        # Impair Defenses and Indicator Removal	Masquerading
        if self.__run_container_process("touch file.txt"):
            self.db_add("defense-evasion", "Detected ability to create and modify files")
        	
        return True

    def __credential_access(self) -> bool:
        # Brute Force: Unabled to programmatically determine at this moment.
        # Steal Application Access Token: Unabled to programmatically determine at this moment.
        # Unsecured Credentials: Unabled to programmatically determine at this moment.
        return True

    def __discovery(self) -> bool:
        # Container and Resource Discovery: Unabled to programmatically determine at this moment.
        # Permission Groups Discovery: Unabled to programmatically determine at this moment.

        # Network Service Discovery	
        if self.package_manager_installed and self.default_user_root:
            self.db_add("network-service-discovery", "Package Manager detected and default user is 'root', can install network scanning tools at will")

        if self.__run_container_process("which wget"):
            self.db_add("network-service-discovery", "Detected wget which allows user to download any network scanning app and run it")

        if self.__run_container_process("which curl"):
            self.db_add("network-service-discovery", "Detected curl which allows user to download any network scanning app and run it")

        if self.__run_container_process("which fetch"):
            self.db_add("network-service-discovery", "Detected fetch which allows user to download any network scanning app and run it")

        return True
    

    def __lateral_movement(self) -> bool:
        # Use Alternate Authentication Material: Unabled to programmatically determine at this moment.
        return True

    def __impact(self) -> bool:
        # Endpoint Denial of Service: Unabled to programmatically determine at this moment.
        # Network Denial of Service: Unabled to programmatically determine at this moment.
        # Resource Hijacking: Logic is in __defense_evasion()
        return True
