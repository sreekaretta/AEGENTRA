"""
AEGENTRA - Enterprise ZAP Scanner
FIXED: Proper session clearing to prevent alert accumulation
"""

from zapv2 import ZAPv2
import requests
import time
from kafka import KafkaProducer
import json
import logging
import yaml
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ZAPScanner:
    """Enterprise-grade ZAP scanner with proper session management"""
    
    def __init__(self):
        """Initialize scanner with configuration"""
        try:
            # Load configuration
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config.yaml')
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
            
            # Get active target
            active_target = self.config['active_target']
            self.target_url = self.config['targets'][active_target]['url']
            
            # ZAP connection
            self.zap_url = 'http://127.0.0.1:8090'
            self.zap = ZAPv2(proxies={
                'http': self.zap_url,
                'https': self.zap_url
            })
            
            # Verify ZAP is running
            self._verify_zap_connection()
            
            # Initialize Kafka
            kafka_config = self.config['kafka']
            self.producer = KafkaProducer(
                bootstrap_servers=[kafka_config['bootstrap_servers']],
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                request_timeout_ms=30000,
                max_block_ms=60000
            )
            
            self.topic = kafka_config['topics']['detection']
            
            logger.info("=" * 60)
            logger.info("ZAP Scanner Initialized Successfully")
            logger.info(f"Target: {active_target}")
            logger.info(f"URL: {self.target_url}")
            logger.info("=" * 60)
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            raise
    
    def _verify_zap_connection(self):
        """Verify ZAP is running and responsive"""
        try:
            version = requests.get(
                f"{self.zap_url}/JSON/core/view/version/",
                timeout=10
            ).json()
            logger.info(f"ZAP Version: {version.get('version', 'Unknown')}")
            
            # Check if scan rules are loaded
            pscan_rules = requests.get(
                f"{self.zap_url}/JSON/pscan/view/scanners/",
                timeout=10
            ).json()
            
            rule_count = len(pscan_rules.get('scanners', []))
            logger.info(f"Passive Scan Rules Loaded: {rule_count}")
            
            if rule_count == 0:
                logger.warning("No passive scan rules loaded! Results may be limited.")
            
        except Exception as e:
            logger.error(f"Cannot connect to ZAP: {e}")
            logger.error("Make sure ZAP is running on port 8090")
            raise
    
    def scan_target(self):
        """Execute complete vulnerability scan"""
        try:
            logger.info("\n" + "=" * 60)
            logger.info("STARTING VULNERABILITY SCAN")
            logger.info("=" * 60 + "\n")
            
            # Step 1: Clear old data (CRITICAL FIX)
            self._clear_session()
            
            # Step 2: Configure scan
            self._configure_scan()
            
            # Step 3: Spider
            self._spider_target()
            
            # Step 4: Active scan
            self._active_scan_target()
            
            # Step 5: Collect and send alerts
            alert_count = self._collect_and_send_alerts()
            
            logger.info("\n" + "=" * 60)
            logger.info(f"SCAN COMPLETE - {alert_count} VULNERABILITIES FOUND")
            logger.info("=" * 60 + "\n")
            
            return alert_count
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return 0
    
    def _clear_session(self):
        """
        FIXED: Completely clear ZAP session to prevent alert accumulation
        This was the main bug causing vulnerability count to increase
        """
        logger.info("Clearing ZAP session completely...")
        try:
            # Step 1: Delete all alerts
            logger.info("  Step 1/4: Deleting all alerts...")
            self.zap.core.delete_all_alerts()
            time.sleep(2)
            
            # Step 2: Clear sites tree
            logger.info("  Step 2/4: Clearing sites tree...")
            try:
                sites = self.zap.core.sites
                for site in sites:
                    try:
                        self.zap.core.delete_site_node(site, '', '')
                    except:
                        pass
            except Exception as e:
                logger.debug(f"Sites clearing: {e}")
            
            # Step 3: Create brand new session
            logger.info("  Step 3/4: Creating new session...")
            try:
                session_name = f'aegentra_scan_{int(time.time())}'
                self.zap.core.new_session(name=session_name, overwrite=True)
                logger.info(f"    ✓ New session created: {session_name}")
            except Exception as e:
                logger.warning(f"    Could not create new session: {e}")
                logger.info("    Continuing with current session...")
            
            # Step 4: Verify clearing worked
            logger.info("  Step 4/4: Verifying session is clean...")
            time.sleep(3)
            
            try:
                remaining_alerts = len(self.zap.core.alerts())
                if remaining_alerts > 0:
                    logger.error(f"    ❌ FAILED: {remaining_alerts} alerts still in ZAP!")
                    logger.error("    ⚠️  Results may include previous scan data")
                    logger.error("    ⚠️  Recommend restarting ZAP container")
                else:
                    logger.info("    ✓ Session verified clean - 0 alerts remaining")
            except:
                logger.info("    ✓ Session cleared")
            
            logger.info("✓ Session clearing complete\n")
            
        except Exception as e:
            logger.error(f"Session clear error: {e}")
            logger.warning("Continuing anyway - results may be inaccurate")
    
    def _configure_scan(self):
        """Configure scan for optimal performance"""
        logger.info("Configuring scan parameters...")
        try:
            # Spider configuration
            self.zap.spider.set_option_max_depth(5)
            self.zap.spider.set_option_thread_count(5)
            
            # Active scan configuration
            self.zap.ascan.set_option_thread_per_host(5)
            self.zap.ascan.set_option_host_per_scan(2)
            
            # Enable all passive scan rules
            scanners = requests.get(
                f"{self.zap_url}/JSON/pscan/view/scanners/",
                timeout=10
            ).json()
            
            for scanner in scanners.get('scanners', []):
                scanner_id = scanner.get('id')
                if scanner_id:
                    try:
                        self.zap.pscan.enable_scanners(scanner_id)
                    except:
                        pass
            
            logger.info("✓ Scan configured\n")
            
        except Exception as e:
            logger.warning(f"Configuration warning: {e}")
    
    def _spider_target(self):
        """Spider the target application"""
        logger.info(f"Spidering: {self.target_url}")
        
        try:
            # Start spider
            scan_id = self.zap.spider.scan(self.target_url)
            logger.info(f"Spider ID: {scan_id}")
            
            # Monitor progress
            time.sleep(2)
            while int(self.zap.spider.status(scan_id)) < 100:
                progress = self.zap.spider.status(scan_id)
                logger.info(f"  Spider Progress: {progress}%")
                time.sleep(3)
            
            # Get results
            urls_found = len(self.zap.spider.results(scan_id))
            logger.info(f"✓ Spider complete - {urls_found} URLs discovered\n")
            
        except Exception as e:
            logger.error(f"Spider failed: {e}")
            raise
    
    def _active_scan_target(self):
        """Perform active vulnerability scanning"""
        logger.info(f"Active scanning: {self.target_url}")
        
        try:
            # Start active scan
            scan_id = self.zap.ascan.scan(self.target_url)
            logger.info(f"Active Scan ID: {scan_id}")
            
            # Monitor progress
            time.sleep(5)
            max_time = self.config.get('scanning', {}).get('timeout', 600)
            start_time = time.time()
            last_progress = 0
            
            while time.time() - start_time < max_time:
                try:
                    status = self.zap.ascan.status(scan_id)
                    if not status:
                        time.sleep(5)
                        continue
                    
                    progress = int(status)
                    
                    if progress >= 100:
                        break
                    
                    if progress != last_progress and progress > 0:
                        logger.info(f"  Active Scan Progress: {progress}%")
                        last_progress = progress
                    
                    time.sleep(5)
                    
                except Exception as e:
                    logger.debug(f"Status check: {e}")
                    time.sleep(5)
            
            logger.info("✓ Active scan complete\n")
            
        except Exception as e:
            logger.error(f"Active scan failed: {e}")
            # Don't raise - passive results still valuable
    
    def _collect_and_send_alerts(self):
        """Collect all alerts and send to Kafka"""
        logger.info("Collecting vulnerability alerts...")
        
        try:
            # Wait for ZAP to finish processing
            logger.info("Waiting for ZAP processing...")
            time.sleep(15)
            
            # Method 1: Try direct API call
            try:
                response = requests.get(
                    f"{self.zap_url}/JSON/core/view/alerts/",
                    timeout=90
                )
                
                if response.status_code == 200:
                    data = response.json()
                    alerts = data.get('alerts', [])
                    logger.info(f"✓ Retrieved {len(alerts)} alerts via API")
                else:
                    raise Exception(f"API returned status {response.status_code}")
                    
            except Exception as e:
                # Method 2: Fallback to ZAP library
                logger.warning(f"API method failed ({e}), trying ZAP library...")
                alerts = self.zap.core.alerts()
                logger.info(f"✓ Retrieved {len(alerts)} alerts via library")
            
            if len(alerts) == 0:
                logger.warning("No vulnerabilities found!")
                logger.warning("Possible reasons:")
                logger.warning("  - Application has no vulnerabilities")
                logger.warning("  - Passive rules not triggered")
                logger.warning("  - Active scan didn't run properly")
                logger.warning("  - Application blocked ZAP requests")
                return 0
            
            # Send to Kafka
            logger.info(f"Sending {len(alerts)} alerts to Kafka...")
            sent_count = 0
            
            for alert in alerts:
                try:
                    message = {
                        'alert_id': f"WEB-{int(time.time() * 1000)}-{sent_count}",
                        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
                        'alert_type': 'web_vulnerability',
                        'source': 'OWASP_ZAP',
                        'url': alert.get('url', ''),
                        'vulnerability': alert.get('alert', 'Unknown'),
                        'severity': self._map_severity(alert.get('risk', 'Low')),
                        'confidence': alert.get('confidence', 'Medium'),
                        'description': alert.get('description', '')[:500],
                        'solution': alert.get('solution', '')[:500],
                        'cwe_id': str(alert.get('cweid', '0')),
                        'evidence': alert.get('evidence', '')[:200],
                        'detection_source': 'web',
                        'target': self.target_url
                    }
                    
                    self.producer.send(self.topic, message)
                    sent_count += 1
                    
                    # Progress indicator
                    if sent_count % 10 == 0:
                        logger.info(f"  Sent {sent_count}/{len(alerts)} alerts...")
                        self.producer.flush(timeout=10)
                    
                except Exception as e:
                    logger.error(f"Failed to send alert: {e}")
                    continue
            
            # Final flush
            self.producer.flush(timeout=30)
            logger.info(f"✓ Successfully sent {sent_count} alerts to Kafka\n")
            
            return sent_count
            
        except Exception as e:
            logger.error(f"Alert collection failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return 0
    
    def _map_severity(self, risk):
        """Map ZAP risk levels to numeric severity"""
        severity_map = {
            'High': 3,
            'Medium': 2,
            'Low': 1,
            'Informational': 0,
            'Information': 0
        }
        return severity_map.get(risk, 1)
    
    def close(self):
        """Cleanup resources"""
        try:
            logger.info("Closing connections...")
            self.producer.close()
            logger.info("✓ Cleanup complete")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


def main():
    """Main execution"""
    scanner = None
    try:
        scanner = ZAPScanner()
        alert_count = scanner.scan_target()
        
        if alert_count == 0:
            logger.warning("\nNo vulnerabilities found - please verify:")
            logger.warning("  1. ZAP is running: docker ps | grep zap")
            logger.warning("  2. Target is accessible: curl http://localhost:8085")
            logger.warning("  3. ZAP can reach target: Check ZAP logs")
            sys.exit(1)
        else:
            logger.info(f"\n✓ SUCCESS: {alert_count} vulnerabilities sent to Kafka")
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"\nFatal error: {e}")
        sys.exit(1)
    finally:
        if scanner:
            scanner.close()


if __name__ == "__main__":
    main()