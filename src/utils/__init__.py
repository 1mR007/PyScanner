# __init__.py

"""
This module initializes global variables for the PyScanner utility.
Attributes:
    stop_event (threading.Event): An event used to signal threads to stop.
    interrupt_handled (bool): A flag indicating whether an interrupt has been handled.
    executor (None): A placeholder for an executor instance, to be initialized later.
"""

import threading

stop_event = threading.Event()
interrupt_handled = False
executor = None