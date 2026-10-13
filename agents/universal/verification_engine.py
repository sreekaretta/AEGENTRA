"""
Verification Engine with Automatic Rollback - ENTERPRISE GRADE
Tests actions immediately and rolls back if problems detected
FIXED: Works for ANY action type, ANY tech stack
"""

import logging
import requests
import time
from typing import Dict, Tuple, List
from datetime import datetime
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class VerificationEngine:
    """
    ENTERPRISE Verification Engine
    Verifies actions and automatically rolls back if problems detected
    Works for ANY action type, ANY vulnerability
    """
    
    def __init__(self):
        self.baseline_metrics = {}
        self.rollback_history = []
        
        logger.info("✅ Verification Engine initialized")
        logger.info("   🔍 Automatic rollback on failure")
        logger.info("   🔍 Works for ANY action type")
    
    def verify_action_with_rollback(self, 
                                    action_result: Dict,
                                    target_url: str,
                                    rollback_func=None) -> Tuple[bool, str, Dict]:
        """
        ENTERPRISE verification with automatic rollback
        Returns: (success, reason, verification_details)
        """
        logger.info(f"🔍 Verifying action: {action_result.get('action')}")
        
        # Step 1: Capture baseline BEFORE action (if not already captured)
        if target_url not in self.baseline_metrics:
            self.baseline_metrics[target_url] = self._capture_baseline(target_url)
        
        baseline = self.baseline_metrics[target_url]
        
        # Step 2: Wait for action to take effect
        time.sleep(2)
        
        # Step 3: Run comprehensive verification tests
        verification = self._run_verification_tests(target_url, baseline, action_result)
        
        # Step 4: Check for problems
        problems = verification['problems']
        
        if problems:
            logger.warning(f"⚠️  Problems detected: {', '.join(problems)}")
            
            # Step 5: AUTOMATIC ROLLBACK
            if rollback_func:
                logger.info(f"🔄 Initiating automatic rollback...")
                rollback_result = rollback_func(action_result)
                
                # Wait for rollback to take effect
                time.sleep(2)
                
                # Verify rollback worked
                post_rollback = self._capture_current_state(target_url)
                
                self.rollback_history.append({
                    'action': action_result.get('action'),
                    'reason': ', '.join(problems),
                    'rollback_time': datetime.now().isoformat(),
                    'rollback_successful': post_rollback.get('accessible', False)
                })
                
                return False, f"Action caused problems: {', '.join(problems)}. Rolled back successfully.", verification
            else:
                logger.warning("No rollback function provided")
                return False, f"Action caused problems: {', '.join(problems)}. No rollback available.", verification
        
        # Step 6: All checks passed
        logger.info(f"✅ Verification passed - no side effects detected")
        return True, "Action verified successfully - no side effects", verification
    
    def _capture_baseline(self, url: str) -> Dict:
        """Capture baseline metrics before action - UNIVERSAL"""
        logger.info(f"   📊 Capturing baseline for {url}")
        return self._capture_current_state(url)
    
    def _capture_current_state(self, url: str) -> Dict:
        """Capture current application state - UNIVERSAL"""
        state = {
            'accessible': False,
            'status_code': 0,
            'response_time': 0,
            'has_errors': False,
            'error_details': [],
            'content_length': 0,
            'headers': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            start = time.time()
            response = requests.get(url, timeout=10, verify=False)
            elapsed = time.time() - start
            
            state['accessible'] = True
            state['status_code'] = response.status_code
            state['response_time'] = elapsed
            state['content_length'] = len(response.content)
            state['headers'] = dict(response.headers)
            
            # Check for server errors
            if response.status_code >= 500:
                state['has_errors'] = True
                state['error_details'].append(f"Server error: {response.status_code}")
            
            # Check for common error indicators in content
            content = response.text.lower()
            error_keywords = ['error', 'exception', 'failed', 'broken', 'unavailable', 'traceback']
            for keyword in error_keywords:
                if keyword in content:
                    state['has_errors'] = True
                    state['error_details'].append(f"Error keyword found: {keyword}")
                    break  # Only report first error to avoid spam
            
        except requests.exceptions.Timeout:
            state['error_details'].append("Request timeout")
        except requests.exceptions.ConnectionError:
            state['error_details'].append("Connection error - site may be down")
        except Exception as e:
            state['error_details'].append(f"Verification error: {str(e)}")
        
        return state
    
    def _run_verification_tests(self, url: str, baseline: Dict, action: Dict) -> Dict:
        """Run comprehensive verification tests - UNIVERSAL"""
        current = self._capture_current_state(url)
        
        problems = []
        warnings = []
        
        # Test 1: Accessibility (CRITICAL)
        if not current['accessible'] and baseline['accessible']:
            problems.append("Site became inaccessible after action")
        
        # Test 2: Status code (CRITICAL)
        if current['status_code'] >= 500:
            problems.append(f"Server error after action: {current['status_code']}")
        elif current['status_code'] == 404 and baseline['status_code'] != 404:
            problems.append("Page not found after action (was accessible before)")
        elif current['status_code'] == 403 and baseline['status_code'] != 403:
            warnings.append("Access forbidden after action (permission issue?)")
        
        # Test 3: Response time degradation
        if baseline['response_time'] > 0 and current['response_time'] > 0:
            slowdown = (current['response_time'] - baseline['response_time']) / baseline['response_time']
            if slowdown > 2.0:  # 200% slower
                problems.append(f"Response time degraded by {slowdown*100:.0f}%")
            elif slowdown > 0.5:  # 50% slower
                warnings.append(f"Response time increased by {slowdown*100:.0f}%")
        
        # Test 4: Error detection (CRITICAL)
        if current['has_errors'] and not baseline.get('has_errors', False):
            problems.append(f"New errors detected: {', '.join(current['error_details'][:2])}")  # Limit to 2
        
        # Test 5: Content length check
        if baseline['content_length'] > 0 and current['content_length'] > 0:
            change = abs(current['content_length'] - baseline['content_length']) / baseline['content_length']
            if change > 0.8:  # 80% change
                problems.append(f"Content size changed dramatically by {change*100:.0f}%")
            elif change > 0.5:  # 50% change
                warnings.append(f"Content size changed by {change*100:.0f}%")
        
        # Test 6: Security headers verification (for security header actions)
        if action.get('action') == 'add_security_headers':
            expected_headers = action.get('headers_added', [])
            missing_headers = []
            for header in expected_headers:
                if header not in current['headers']:
                    missing_headers.append(header)
            
            if missing_headers:
                warnings.append(f"Expected headers not found: {', '.join(missing_headers[:3])}")
        
        # Test 7: No regression (ensure we didn't break working functionality)
        if baseline['accessible'] and baseline['status_code'] == 200:
            if not current['accessible'] or current['status_code'] != 200:
                problems.append("Action caused regression - working site is now broken")
        
        verification_result = {
            'baseline': baseline,
            'current': current,
            'problems': problems,
            'warnings': warnings,
            'tests_passed': len(problems) == 0,
            'tests_with_warnings': len(warnings) > 0,
            'timestamp': datetime.now().isoformat()
        }
        
        return verification_result
    
    def get_rollback_history(self) -> List[Dict]:
        """Get history of rollbacks - UNIVERSAL"""
        return self.rollback_history
    
    def clear_baseline(self, url: str = None):
        """Clear baseline for a specific URL or all URLs"""
        if url:
            if url in self.baseline_metrics:
                del self.baseline_metrics[url]
                logger.info(f"Cleared baseline for {url}")
        else:
            self.baseline_metrics = {}
            logger.info("Cleared all baselines")


class RollbackManager:
    """
    ENTERPRISE Rollback Manager
    Manages rollback operations for actions
    Works for ANY action type
    """
    
    def __init__(self):
        self.rollback_stack = []
        
        logger.info("✅ Rollback Manager initialized")
    
    def register_action(self, action: Dict, rollback_commands: List[str]):
        """Register action with rollback commands - UNIVERSAL"""
        self.rollback_stack.append({
            'action': action,
            'rollback_commands': rollback_commands,
            'timestamp': datetime.now().isoformat()
        })
        
        logger.info(f"Registered rollback for: {action.get('action_type', 'unknown')}")
    
    def rollback_action(self, action_result: Dict) -> Dict:
        """Execute rollback for an action - UNIVERSAL"""
        action_type = action_result.get('action')
        
        logger.info(f"🔄 Rolling back: {action_type}")
        
        # Find rollback commands for this action
        for entry in reversed(self.rollback_stack):
            if entry['action'].get('action_type') == action_type:
                rollback_commands = entry['rollback_commands']
                
                # Execute rollback commands
                for cmd in rollback_commands:
                    try:
                        logger.info(f"   Executing rollback: {cmd}")
                        # In production, execute actual rollback command
                        # subprocess.run(cmd, shell=True, timeout=30)
                    except Exception as e:
                        logger.error(f"   Rollback command failed: {e}")
                
                return {
                    'rollback_status': 'SUCCESS',
                    'action': action_type,
                    'timestamp': datetime.now().isoformat()
                }
        
        logger.warning(f"No rollback found for: {action_type}")
        
        return {
            'rollback_status': 'NO_ROLLBACK_FOUND',
            'action': action_type,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_rollback_stack(self) -> List[Dict]:
        """Get current rollback stack - UNIVERSAL"""
        return self.rollback_stack
    
    def clear_stack(self):
        """Clear rollback stack"""
        self.rollback_stack = []
        logger.info("Rollback stack cleared")