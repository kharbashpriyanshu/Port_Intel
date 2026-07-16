import logging
import sys

def setup_logger(name: str, verbose: bool = False, debug: bool = False) -> logging.Logger:
    """
    Sets up and returns a customized logger.
    """
    logger = logging.getLogger(name)
    
    # Avoid adding multiple handlers if logger is already configured
    if logger.hasHandlers():
        logger.handlers.clear()
        
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    
    if debug:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        # For regular use, make it look clean like the original tool
        formatter = logging.Formatter('%(message)s')
        
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger
