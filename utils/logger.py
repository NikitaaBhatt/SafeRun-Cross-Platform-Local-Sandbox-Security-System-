# saferun/utils/logger.py
import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from saferun.config import settings

class LogManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LogManager, cls).__new__(cls)
            cls._instance._initialize_logging()
        return cls._instance
    
    def _initialize_logging(self):
        """Initialize logging configuration"""
        # Ensure log directory exists
        os.makedirs(settings.LOG_DIR, exist_ok=True)
        
        # Set up logging format
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        date_format = '%Y-%m-%d %H:%M:%S'
        formatter = logging.Formatter(log_format, date_format)
        
        # Set up root logger
        self.root_logger = logging.getLogger('saferun')
        self.root_logger.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.root_logger.addHandler(console_handler)
        
        # File handler
        main_log_file = os.path.join(settings.LOG_DIR, 'saferun.log')
        file_handler = RotatingFileHandler(
            main_log_file, 
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        self.root_logger.addHandler(file_handler)
        
        self.loggers = {}
    
    def get_logger(self, name):
        """Get a named logger
        
        Args:
            name (str): Logger name
            
        Returns:
            logging.Logger: Configured logger
        """
        logger_name = f'saferun.{name}'
        
        if logger_name in self.loggers:
            return self.loggers[logger_name]
        
        # Create a new logger
        logger = logging.getLogger(logger_name)
        
        # Create a specific log file for this component
        component_log_file = os.path.join(settings.LOG_DIR, f'{name}.log')
        component_handler = RotatingFileHandler(
            component_log_file, 
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        component_handler.setLevel(logging.DEBUG)
        component_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s', 
            '%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(component_handler)
        
        self.loggers[logger_name] = logger
        return logger