#!/usr/bin/env python3
"""
Rules Config CLI Manager
Tool cho admin quản lý behavioral rules config từ command line

Cách sử dụng:
    python rules_cli_manager.py list-apps
    python rules_cli_manager.py add-app chrome.exe --type browser
    python rules_cli_manager.py add-domain slack.com
    python rules_cli_manager.py remove-app telegram.exe --type messaging
    python rules_cli_manager.py stats
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional
from rules_config_manager import RulesConfigManager, get_config_manager


class RulesConfigCLI:
    """CLI tool để quản lý config"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.manager = RulesConfigManager(config_file)
    
    def list_apps(self, app_type: str = 'all'):
        """Liệt kê tất cả apps"""
        if app_type in ['browser', 'all']:
            apps = self.manager.get_browser_apps()
            print(f"\n=== Browser Apps ({len(apps)}) ===")
            for app in sorted(apps):
                print(f"  • {app}")
        
        if app_type in ['messaging', 'all']:
            apps = self.manager.get_messaging_apps()
            print(f"\n=== Messaging Apps ({len(apps)}) ===")
            for app in sorted(apps):
                print(f"  • {app}")
    
    def list_domains(self):
        """Liệt kê tất cả sensitive domains"""
        domains = self.manager.get_sensitive_domains()
        print(f"\n=== Sensitive Domains ({len(domains)}) ===")
        for domain in sorted(domains):
            print(f"  • {domain}")
    
    def list_keywords(self):
        """Liệt kê tất cả sensitive keywords"""
        keywords = self.manager.get_sensitive_title_keywords()
        print(f"\n=== Sensitive Keywords ({len(keywords)}) ===")
        for keyword in sorted(keywords):
            print(f"  • {keyword}")
    
    def list_drives(self):
        """Liệt kê tất cả removable drives"""
        drives = self.manager.get_removable_drives()
        print(f"\n=== Removable Drives ({len(drives)}) ===")
        for drive in sorted(drives):
            print(f"  • {drive}")
    
    def add_app(self, app_name: str, app_type: str):
        """Thêm app"""
        if app_type == 'browser':
            self.manager.add_browser_app(app_name)
            print(f"[v] Browser app '{app_name}' added")
        elif app_type == 'messaging':
            if 'messaging_apps' not in self.manager.config['clipboard_paste_rule']:
                self.manager.config['clipboard_paste_rule']['messaging_apps'] = []
            if app_name not in self.manager.config['clipboard_paste_rule']['messaging_apps']:
                self.manager.config['clipboard_paste_rule']['messaging_apps'].append(app_name)
                print(f"[v] Messaging app '{app_name}' added")
            else:
                print(f"! App '{app_name}' already exists")
        
        self.manager.save_config()
    
    def add_domain(self, domain: str):
        """Thêm domain nhạy cảm"""
        self.manager.add_sensitive_domain(domain)
        self.manager.save_config()
        print(f"[v] Domain '{domain}' added to sensitive list")
    
    def add_keyword(self, keyword: str):
        """Thêm keyword"""
        if 'clipboard_paste_rule' not in self.manager.config:
            self.manager.config['clipboard_paste_rule'] = {}
        if 'sensitive_title_keywords' not in self.manager.config['clipboard_paste_rule']:
            self.manager.config['clipboard_paste_rule']['sensitive_title_keywords'] = []
        
        if keyword not in self.manager.config['clipboard_paste_rule']['sensitive_title_keywords']:
            self.manager.config['clipboard_paste_rule']['sensitive_title_keywords'].append(keyword)
            self.manager.save_config()
            print(f"[v] Keyword '{keyword}' added")
        else:
            print(f"! Keyword '{keyword}' already exists")
    
    def add_drive(self, drive: str):
        """Thêm removable drive"""
        if 'usb_rule' not in self.manager.config:
            self.manager.config['usb_rule'] = {}
        if 'removable_drives' not in self.manager.config['usb_rule']:
            self.manager.config['usb_rule']['removable_drives'] = []
        
        if drive not in self.manager.config['usb_rule']['removable_drives']:
            self.manager.config['usb_rule']['removable_drives'].append(drive)
            self.manager.save_config()
            print(f"[v] Drive '{drive}' added")
        else:
            print(f"! Drive '{drive}' already exists")
    
    def remove_app(self, app_name: str, app_type: str):
        """Xóa app"""
        self.manager.remove_app(app_name, app_type=f"{app_type}_apps")
        self.manager.save_config()
        print(f"[v] App '{app_name}' removed from {app_type}_apps")
    
    def remove_domain(self, domain: str):
        """Xóa domain"""
        domains = self.manager.config.get('clipboard_paste_rule', {}).get('sensitive_domains', [])
        if domain in domains:
            domains.remove(domain)
            self.manager.save_config()
            print(f"[v] Domain '{domain}' removed")
        else:
            print(f"! Domain '{domain}' not found")
    
    def search(self, query: str):
        """Tìm kiếm app/domain/keyword"""
        query = query.lower()
        print(f"\n=== Search Results for '{query}' ===\n")
        
        # Search apps
        found = False
        for app in self.manager.get_browser_apps():
            if query in app.lower():
                print(f"Browser App: {app}")
                found = True
        
        for app in self.manager.get_messaging_apps():
            if query in app.lower():
                print(f"Messaging App: {app}")
                found = True
        
        # Search domains
        for domain in self.manager.get_sensitive_domains():
            if query in domain.lower():
                print(f"Domain: {domain}")
                found = True
        
        # Search keywords
        for keyword in self.manager.get_sensitive_title_keywords():
            if query in keyword.lower():
                print(f"Keyword: {keyword}")
                found = True
        
        if not found:
            print("No results found")
    
    def show_stats(self):
        """Hiển thị thống kê"""
        print("\n=== Config Statistics ===")
        print(f"Browser Apps:             {len(self.manager.get_browser_apps())}")
        print(f"Messaging Apps:           {len(self.manager.get_messaging_apps())}")
        print(f"Sensitive Domains:        {len(self.manager.get_sensitive_domains())}")
        print(f"Sensitive Keywords:       {len(self.manager.get_sensitive_title_keywords())}")
        print(f"Removable Drives:         {len(self.manager.get_removable_drives())}")
        print(f"Network Upload Types:     {len(self.manager.get_upload_types())}")
        print()
    
    def export(self, output_file: str):
        """Export config to JSON"""
        output_path = Path(output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.manager.config, f, indent=2, ensure_ascii=False)
        print(f"[v] Config exported to {output_path}")
    
    def import_config(self, input_file: str):
        """Import config from JSON"""
        input_path = Path(input_file)
        if not input_path.exists():
            print(f"[x] File not found: {input_path}")
            return
        
        with open(input_path, 'r', encoding='utf-8') as f:
            imported_config = json.load(f)
        
        self.manager.update_config(imported_config)
        self.manager.save_config()
        print(f"[v] Config imported from {input_path}")


def main():
    parser = argparse.ArgumentParser(
        description="HybridDLP Behavioral Rules Config Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all apps
  python rules_cli_manager.py list-apps
  
  # Add browser app
  python rules_cli_manager.py add-app opera.exe --type browser
  
  # Add messaging app
  python rules_cli_manager.py add-app viber.exe --type messaging
  
  # Add sensitive domain
  python rules_cli_manager.py add-domain slack.mycompany.com
  
  # Remove app
  python rules_cli_manager.py remove-app telegram.exe --type messaging
  
  # Search
  python rules_cli_manager.py search slack
  
  # Show statistics
  python rules_cli_manager.py stats
  
  # Export config
  python rules_cli_manager.py export config_backup.json
  
  # Import config
  python rules_cli_manager.py import config_new.json
        """
    )
    
    parser.add_argument('--config', help='Path to rules_config.json')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List commands
    subparsers.add_parser('list-apps', help='List all apps')
    subparsers.add_parser('list-domains', help='List all sensitive domains')
    subparsers.add_parser('list-keywords', help='List all sensitive keywords')
    subparsers.add_parser('list-drives', help='List all removable drives')
    
    # Add commands
    add_app = subparsers.add_parser('add-app', help='Add an app')
    add_app.add_argument('app_name')
    add_app.add_argument('--type', choices=['browser', 'messaging'], default='browser')
    
    add_domain = subparsers.add_parser('add-domain', help='Add a sensitive domain')
    add_domain.add_argument('domain')
    
    add_keyword = subparsers.add_parser('add-keyword', help='Add a sensitive keyword')
    add_keyword.add_argument('keyword')
    
    add_drive = subparsers.add_parser('add-drive', help='Add a removable drive')
    add_drive.add_argument('drive')
    
    # Remove commands
    remove_app = subparsers.add_parser('remove-app', help='Remove an app')
    remove_app.add_argument('app_name')
    remove_app.add_argument('--type', choices=['browser', 'messaging'], default='browser')
    
    remove_domain = subparsers.add_parser('remove-domain', help='Remove a domain')
    remove_domain.add_argument('domain')
    
    # Other commands
    subparsers.add_parser('stats', help='Show config statistics')
    
    search = subparsers.add_parser('search', help='Search in config')
    search.add_argument('query')
    
    export = subparsers.add_parser('export', help='Export config to JSON')
    export.add_argument('output_file')
    
    import_cmd = subparsers.add_parser('import', help='Import config from JSON')
    import_cmd.add_argument('input_file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize CLI
    cli = RulesConfigCLI(args.config)
    
    # Execute command
    try:
        if args.command == 'list-apps':
            cli.list_apps()
        elif args.command == 'list-domains':
            cli.list_domains()
        elif args.command == 'list-keywords':
            cli.list_keywords()
        elif args.command == 'list-drives':
            cli.list_drives()
        elif args.command == 'add-app':
            cli.add_app(args.app_name, args.type)
        elif args.command == 'add-domain':
            cli.add_domain(args.domain)
        elif args.command == 'add-keyword':
            cli.add_keyword(args.keyword)
        elif args.command == 'add-drive':
            cli.add_drive(args.drive)
        elif args.command == 'remove-app':
            cli.remove_app(args.app_name, args.type)
        elif args.command == 'remove-domain':
            cli.remove_domain(args.domain)
        elif args.command == 'stats':
            cli.show_stats()
        elif args.command == 'search':
            cli.search(args.query)
        elif args.command == 'export':
            cli.export(args.output_file)
        elif args.command == 'import':
            cli.import_config(args.input_file)
    except Exception as e:
        print(f"[x] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
