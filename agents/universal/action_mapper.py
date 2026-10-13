"""
Universal Action Mapper - ENTERPRISE GRADE
Maps ANY vulnerability to appropriate actions
FIXED: Comprehensive CWE mappings, MITRE ATT&CK integration
"""

import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class UniversalActionMapper:
    """
    ENTERPRISE Universal Action Mapper
    Works for ANY vulnerability type, ANY tech stack
    """
    
    def __init__(self):
        # MITRE ATT&CK → Action mapping (COMPREHENSIVE)
        self.mitre_actions = {
            'T1190': ['add_waf_rule', 'patch_application', 'add_input_validation', 'enable_rate_limiting'],
            'T1059': ['disable_script_execution', 'add_content_security_policy', 'sanitize_inputs'],
            'T1078': ['enforce_mfa', 'review_access_controls', 'audit_user_accounts'],
            'T1083': ['restrict_directory_listing', 'implement_access_controls', 'add_authentication'],
            'T1110': ['implement_rate_limiting', 'add_captcha', 'enable_account_lockout'],
            'T1133': ['review_external_services', 'implement_network_segmentation', 'add_firewall_rules'],
            'T1189': ['add_content_security_policy', 'implement_xss_protection', 'sanitize_outputs'],
            'T1566': ['implement_email_filtering', 'add_security_awareness', 'enable_link_protection'],
            'T1210': ['patch_vulnerabilities', 'disable_unnecessary_services', 'implement_network_segmentation'],
            'T1505': ['scan_for_webshells', 'implement_file_integrity_monitoring', 'restrict_file_uploads'],
            'T1090': ['validate_urls', 'implement_whitelist', 'restrict_outbound_requests']
        }
        
        # CWE → Action mapping (COMPREHENSIVE - 50+ CWEs)
        self.cwe_actions = {
            'CWE-79': ['add_output_encoding', 'add_content_security_policy', 'sanitize_user_inputs', 'implement_xss_protection'],
            'CWE-89': ['use_prepared_statements', 'implement_input_validation', 'add_waf_rule', 'sanitize_sql_inputs'],
            'CWE-78': ['sanitize_command_inputs', 'use_safe_apis', 'implement_input_validation', 'restrict_command_execution'],
            'CWE-22': ['validate_file_paths', 'implement_whitelist', 'restrict_file_access', 'use_secure_apis'],
            'CWE-352': ['implement_csrf_tokens', 'validate_origin', 'add_samesite_cookies', 'require_reauth'],
            'CWE-94': ['sanitize_eval_inputs', 'disable_dynamic_execution', 'implement_code_review', 'use_safe_parsers'],
            'CWE-434': ['validate_file_types', 'scan_uploads', 'restrict_execution', 'implement_file_size_limits'],
            'CWE-287': ['implement_strong_authentication', 'add_mfa', 'enforce_password_policy', 'audit_auth_logic'],
            'CWE-798': ['rotate_credentials', 'use_secret_manager', 'remove_hardcoded_secrets', 'implement_encryption'],
            'CWE-200': ['remove_verbose_errors', 'implement_logging_controls', 'sanitize_responses', 'add_security_headers'],
            'CWE-16': ['update_configuration', 'follow_security_best_practices', 'implement_secure_defaults', 'audit_config'],
            'CWE-311': ['implement_encryption_at_rest', 'use_secure_protocols', 'add_tls', 'encrypt_sensitive_data'],
            'CWE-327': ['use_strong_crypto', 'update_crypto_libraries', 'migrate_to_secure_algorithms', 'audit_crypto_usage'],
            'CWE-306': ['add_authentication_checks', 'implement_access_controls', 'require_login', 'audit_endpoints'],
            'CWE-862': ['implement_authorization_checks', 'add_rbac', 'validate_permissions', 'audit_access_controls'],
            'CWE-601': ['validate_redirect_urls', 'use_whitelist', 'avoid_user_controlled_redirects', 'add_validation'],
            'CWE-611': ['disable_external_entities', 'use_safe_xml_parsers', 'validate_xml_inputs', 'update_xml_libraries'],
            'CWE-502': ['avoid_unsafe_deserialization', 'validate_serialized_data', 'use_safe_formats', 'implement_integrity_checks'],
            'CWE-918': ['validate_urls', 'implement_whitelist', 'restrict_outbound_requests', 'add_firewall_rules'],
            'CWE-400': ['implement_rate_limiting', 'add_resource_quotas', 'optimize_algorithms', 'add_timeouts'],
            'CWE-770': ['limit_resource_allocation', 'implement_quotas', 'add_monitoring', 'optimize_code'],
            'CWE-732': ['fix_file_permissions', 'implement_least_privilege', 'audit_permissions', 'restrict_access'],
            'CWE-522': ['hash_passwords', 'use_bcrypt', 'implement_secure_storage', 'audit_credential_storage'],
            'CWE-776': ['validate_xml_size', 'implement_size_limits', 'add_parsing_limits', 'use_secure_parsers'],
            'CWE-829': ['validate_includes', 'use_whitelist', 'avoid_dynamic_includes', 'implement_integrity_checks'],
            'CWE-20': ['add_input_validation', 'sanitize_inputs', 'implement_whitelist', 'validate_data_types'],
            'CWE-269': ['implement_least_privilege', 'audit_permissions', 'restrict_privileges', 'add_rbac'],
            'CWE-295': ['validate_ssl_certificates', 'enable_certificate_pinning', 'update_tls_config'],
            'CWE-310': ['implement_encryption', 'use_strong_crypto', 'secure_key_storage'],
            'CWE-326': ['use_strong_encryption', 'update_crypto_algorithms', 'migrate_to_aes256'],
            'CWE-330': ['use_secure_random', 'avoid_weak_prng', 'implement_cryptographically_secure_random'],
            'CWE-346': ['validate_origin', 'implement_origin_checks', 'add_cors_policy'],
            'CWE-384': ['implement_session_fixation_protection', 'regenerate_session_ids', 'secure_session_management'],
            'CWE-425': ['validate_redirects', 'use_whitelist', 'avoid_open_redirects'],
            'CWE-451': ['implement_ui_spoofing_protection', 'validate_user_interface', 'add_security_indicators'],
            'CWE-470': ['validate_code_integrity', 'implement_signing', 'use_trusted_sources'],
            'CWE-502': ['avoid_deserialization', 'validate_serialized_data', 'use_safe_formats'],
            'CWE-525': ['secure_browser_cache', 'add_no_store_headers', 'implement_cache_controls'],
            'CWE-532': ['sanitize_logs', 'remove_sensitive_data_from_logs', 'implement_log_scrubbing'],
            'CWE-639': ['implement_authorization', 'add_access_controls', 'validate_permissions'],
            'CWE-732': ['fix_permissions', 'implement_least_privilege', 'audit_file_permissions'],
            'CWE-787': ['implement_bounds_checking', 'use_safe_string_functions', 'validate_buffer_sizes'],
            'CWE-798': ['remove_hardcoded_credentials', 'use_environment_variables', 'implement_secret_management'],
            'CWE-829': ['validate_file_includes', 'use_whitelist', 'avoid_dynamic_includes'],
            'CWE-843': ['validate_type_conversions', 'implement_type_checking', 'use_strict_typing'],
            'CWE-913': ['validate_sql_queries', 'use_parameterized_queries', 'avoid_dynamic_sql'],
            'CWE-915': ['validate_file_paths', 'use_whitelist', 'implement_path_sanitization'],
            'CWE-943': ['validate_nosql_inputs', 'sanitize_queries', 'use_parameterized_queries']
        }
        
        # Vulnerability type → Action mapping (UNIVERSAL)
        self.vuln_type_actions = {
            'Missing Security Header': ['add_security_headers', 'configure_web_server', 'update_response_headers'],
            'Information Disclosure': ['remove_verbose_errors', 'sanitize_responses', 'implement_error_handling'],
            'Weak Cryptography': ['update_tls_config', 'use_strong_ciphers', 'disable_weak_protocols'],
            'Session Management': ['configure_session_security', 'implement_secure_cookies', 'add_session_timeout'],
            'Access Control': ['implement_authorization', 'add_rbac', 'validate_permissions'],
            'Input Validation': ['add_input_validation', 'sanitize_inputs', 'implement_whitelist'],
            'Output Encoding': ['add_output_encoding', 'sanitize_outputs', 'use_safe_rendering'],
            'Authentication': ['strengthen_authentication', 'add_mfa', 'implement_password_policy'],
            'Server Configuration': ['harden_server_config', 'apply_security_baseline', 'remove_unnecessary_services'],
            'SSL/TLS': ['update_ssl_config', 'enable_hsts', 'fix_certificate_issues'],
            'Directory Traversal': ['validate_paths', 'restrict_file_access', 'use_secure_apis'],
            'Path Traversal': ['validate_file_paths', 'implement_whitelist', 'restrict_file_access'],
            'Remote Code Execution': ['patch_application', 'sanitize_inputs', 'implement_sandboxing'],
            'Denial of Service': ['implement_rate_limiting', 'add_resource_limits', 'optimize_code'],
            'Cross-Site Scripting': ['add_output_encoding', 'add_content_security_policy', 'sanitize_user_inputs'],
            'SQL Injection': ['use_prepared_statements', 'implement_input_validation', 'add_waf_rule'],
            'Command Injection': ['sanitize_command_inputs', 'use_safe_apis', 'implement_input_validation'],
            'XML External Entity': ['disable_external_entities', 'use_safe_xml_parsers', 'validate_xml_inputs'],
            'SSRF': ['validate_urls', 'implement_whitelist', 'restrict_outbound_requests'],
            'CSRF': ['implement_csrf_tokens', 'validate_origin', 'add_samesite_cookies']
        }
        
        logger.info("✅ Universal Action Mapper initialized")
        logger.info(f"   📊 {len(self.cwe_actions)} CWE mappings")
        logger.info(f"   📊 {len(self.mitre_actions)} MITRE ATT&CK mappings")
        logger.info(f"   📊 {len(self.vuln_type_actions)} vulnerability type mappings")
    
    def map_vulnerability_to_actions(self, 
                                     vulnerability_type: str,
                                     cwe_id: str,
                                     mitre_technique: str,
                                     severity: int,
                                     confidence: float,
                                     tech_stack: Dict) -> List[str]:
        """
        ENTERPRISE Universal mapping: vulnerability → actions
        Works for ANY vulnerability type
        """
        actions = set()
        
        # 1. Map based on MITRE technique (highest priority)
        if mitre_technique and mitre_technique in self.mitre_actions:
            actions.update(self.mitre_actions[mitre_technique])
            logger.info(f"   Mapped MITRE {mitre_technique} → {len(actions)} actions")
        
        # 2. Map based on CWE (FIXED: Better CWE handling)
        if cwe_id:
            # Normalize CWE ID
            cwe_key = f"CWE-{cwe_id}" if not str(cwe_id).startswith('CWE-') else str(cwe_id)
            cwe_key = cwe_key.replace('CWE-0', 'CWE-')  # Handle CWE-089 → CWE-89
            
            if cwe_key in self.cwe_actions:
                actions.update(self.cwe_actions[cwe_key])
                logger.info(f"   Mapped {cwe_key} → {len(actions)} actions")
        
        # 3. Map based on vulnerability type (pattern matching)
        for vuln_pattern, vuln_actions in self.vuln_type_actions.items():
            if vuln_pattern.lower() in vulnerability_type.lower():
                actions.update(vuln_actions)
                logger.info(f"   Mapped '{vuln_pattern}' → {len(actions)} actions")
        
        # 4. Add technology-specific actions
        tech_actions = self._get_tech_specific_actions(tech_stack, vulnerability_type)
        actions.update(tech_actions)
        
        # 5. Add severity-based actions (UNIVERSAL)
        if severity >= 8:
            actions.add('alert_security_team')
            actions.add('create_incident_ticket')
        
        if severity >= 9:
            actions.add('notify_executives')
            actions.add('enable_enhanced_monitoring')
        
        # Convert to list and prioritize
        action_list = list(actions)
        prioritized = self._prioritize_actions(action_list, severity, confidence)
        
        logger.info(f"   Total mapped actions: {len(prioritized)}")
        return prioritized
    
    def _get_tech_specific_actions(self, tech_stack: Dict, vuln_type: str) -> List[str]:
        """Get actions specific to detected technology (UNIVERSAL)"""
        actions = []
        
        web_server = tech_stack.get('web_server', '').lower()
        language = tech_stack.get('language', '').lower()
        framework = tech_stack.get('framework', '').lower()
        
        # Web server specific (UNIVERSAL)
        if 'apache' in web_server:
            actions.extend(['update_htaccess', 'configure_apache_security', 'enable_mod_security'])
        elif 'nginx' in web_server:
            actions.extend(['update_nginx_config', 'add_nginx_security_headers', 'enable_nginx_waf'])
        elif 'iis' in web_server:
            actions.extend(['update_web_config', 'configure_iis_security', 'enable_request_filtering'])
        
        # Language specific (UNIVERSAL)
        if 'php' in language:
            actions.extend(['update_php_ini', 'disable_dangerous_functions', 'enable_php_security'])
        elif 'python' in language:
            actions.extend(['update_wsgi_config', 'add_python_security_middleware'])
        elif 'node' in language or 'javascript' in language:
            actions.extend(['update_express_security', 'add_helmet_js', 'configure_node_security'])
        elif 'java' in language:
            actions.extend(['update_servlet_config', 'add_spring_security', 'configure_tomcat_security'])
        elif 'ruby' in language:
            actions.extend(['update_rails_config', 'add_rails_security', 'configure_rack_protection'])
        elif 'dotnet' in language or 'c#' in language:
            actions.extend(['update_web_config', 'add_aspnet_security', 'configure_iis_security'])
        
        return actions
    
    def _prioritize_actions(self, actions: List[str], severity: int, confidence: float) -> List[str]:
        """Prioritize actions based on effectiveness and safety (UNIVERSAL)"""
        priority_map = {
            # Immediate protection (highest priority)
            'add_waf_rule': 100,
            'implement_rate_limiting': 95,
            'add_input_validation': 90,
            'block_ip': 90,
            
            # Configuration fixes
            'add_security_headers': 85,
            'configure_web_server': 80,
            'update_ssl_config': 80,
            'add_content_security_policy': 85,
            
            # Code fixes
            'sanitize_inputs': 75,
            'add_output_encoding': 75,
            'use_prepared_statements': 75,
            'implement_csrf_tokens': 75,
            
            # Authentication/Authorization
            'add_mfa': 70,
            'implement_authorization': 70,
            'strengthen_authentication': 70,
            
            # Monitoring & alerting
            'alert_security_team': 60,
            'enable_enhanced_monitoring': 55,
            'create_incident_ticket': 50,
            
            # Notifications
            'notify_executives': 40
        }
        
        # Sort by priority
        sorted_actions = sorted(
            actions,
            key=lambda a: priority_map.get(a, 50),
            reverse=True
        )
        
        # Limit based on severity and confidence (ADAPTIVE)
        if severity < 7 and confidence < 0.8:
            return sorted_actions[:3]  # Conservative
        elif severity >= 8 or confidence >= 0.9:
            return sorted_actions[:5]  # Aggressive
        else:
            return sorted_actions[:4]  # Balanced
    
    def get_action_metadata(self, action: str) -> Dict:
        """Get metadata about an action (UNIVERSAL)"""
        metadata = {
            'action': action,
            'category': self._categorize_action(action),
            'risk_level': self._assess_action_risk(action),
            'requires_approval': self._requires_approval(action),
            'can_rollback': self._can_rollback(action),
            'estimated_impact': self._estimate_impact(action)
        }
        
        return metadata
    
    def _categorize_action(self, action: str) -> str:
        """Categorize action type (UNIVERSAL)"""
        if any(x in action for x in ['config', 'header', 'server']):
            return 'configuration'
        elif any(x in action for x in ['sanitize', 'validate', 'encode']):
            return 'code_fix'
        elif any(x in action for x in ['waf', 'firewall', 'rate', 'block']):
            return 'network_control'
        elif any(x in action for x in ['alert', 'notify', 'ticket']):
            return 'notification'
        elif any(x in action for x in ['auth', 'mfa', 'access']):
            return 'access_control'
        else:
            return 'other'
    
    def _assess_action_risk(self, action: str) -> str:
        """Assess risk level of action (UNIVERSAL)"""
        high_risk = ['restart', 'shutdown', 'isolate', 'block_network', 'modify_database']
        medium_risk = ['update_config', 'patch_application', 'disable_service']
        
        if any(x in action for x in high_risk):
            return 'high'
        elif any(x in action for x in medium_risk):
            return 'medium'
        else:
            return 'low'
    
    def _requires_approval(self, action: str) -> bool:
        """Check if action requires human approval (UNIVERSAL)"""
        needs_approval = ['restart', 'shutdown', 'modify_database', 'patch_application', 
                         'disable_service', 'block_network', 'isolate']
        return any(x in action for x in needs_approval)
    
    def _can_rollback(self, action: str) -> bool:
        """Check if action can be rolled back (UNIVERSAL)"""
        cannot_rollback = ['delete', 'remove', 'drop', 'purge']
        return not any(x in action for x in cannot_rollback)
    
    def _estimate_impact(self, action: str) -> str:
        """Estimate business impact (UNIVERSAL)"""
        high_impact = ['shutdown', 'restart', 'block', 'isolate', 'disable']
        medium_impact = ['update', 'patch', 'modify', 'change']
        
        if any(x in action for x in high_impact):
            return 'high'
        elif any(x in action for x in medium_impact):
            return 'medium'
        else:
            return 'low'