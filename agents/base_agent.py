"""
Base Agent for Aegentra Multi-Agent System
FIXED: Removed duplicate topic subscription, corrected timeouts
"""

from kafka import KafkaConsumer, KafkaProducer
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BaseAgent:
    """Base class for all agents in the Aegentra system"""
    
    def __init__(self, agent_name, input_topic, output_topic=None, consumer_kwargs=None):
        self.agent_name = agent_name
        self.input_topic = input_topic
        self.output_topic = output_topic

        consumer_config = {
            'bootstrap_servers': ['localhost:9092'],
            'value_deserializer': lambda m: json.loads(m.decode('utf-8')),
            'group_id': f"{self.agent_name}-group",
            'auto_offset_reset': 'earliest',
            'enable_auto_commit': False,
            'max_poll_interval_ms': 300000,   # 5 minutes (default)
            'session_timeout_ms': 30000,      # 30 seconds
        }
        if consumer_kwargs:
            consumer_config.update(consumer_kwargs)

        # Create Kafka consumer - FIXED: Subscribe only once
        self.consumer = KafkaConsumer(input_topic, **consumer_config)
        
        # Create Kafka producer (if output topic specified)
        self.producer = None
        if output_topic:
            self.producer = KafkaProducer(
                bootstrap_servers=['localhost:9092'],
                value_serializer=lambda x: json.dumps(x).encode('utf-8'),
                request_timeout_ms=30000
            )
        
        logger.info(f"{agent_name} initialized")
        logger.info(f"Consuming from: {input_topic}")
        if output_topic:
            logger.info(f"Producing to: {output_topic}")
    
    def deserialize_message(self, message):
        """Deserialize Kafka message"""
        return message.value
    
    def process_message(self, message):
        """Process individual message - must be implemented by subclass"""
        raise NotImplementedError("Subclasses must implement process_message()")
    
    def run(self):
        """Main loop: consume messages, process, and produce results"""
        logger.info(f"{self.agent_name} starting...")
        
        try:
            for message in self.consumer:
                decoded_message = self.deserialize_message(message)
                
                if decoded_message:
                    msg_id = decoded_message.get('incident_id', decoded_message.get('alert_id', 'unknown'))
                    logger.info(f"Received message: {msg_id}")
                    
                    # Process message
                    result = self.process_message(decoded_message)
                    
                    # Send result if exists and producer is configured
                    if result and self.producer:
                        self.producer.send(self.output_topic, result)
                        self.producer.flush(timeout=10)
                    
                    # Commit offset after successful processing
                    self.consumer.commit()
                    
        except KeyboardInterrupt:
            logger.info(f"{self.agent_name} stopping...")
            self.cleanup()
        except Exception as e:
            logger.error(f"Error in {self.agent_name}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Cleanup resources"""
        logger.info("Closing Kafka connections...")
        if self.consumer:
            self.consumer.close()
        if self.producer:
            self.producer.close()