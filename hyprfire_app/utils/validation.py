import logging
from decimal import Decimal, InvalidOperation
from math import isinf
from pathlib import Path

from hyprfire_app.exceptions import TimestampException

MAX_TIMESTAMP = 32503680000


def validate_file_path(file_path):
    """
    validate_file_path

    A file path is valid if it points to an existing file

    Parameters
    file_path: a string representation of a file path

    Return
    The file path if it points to a valid file
    """
    path = Path(file_path)
    name = path.stem.lower()

    if not path.is_file() and not name.startswith('.'):
        raise FileNotFoundError('File Not Found.')

    return str(path)


def validate_timestamp(timestamp):
    """
    validate_timestamp

    A timestamp is valid if it represents a date between 1970-01-01 00:00:00 and 3000-01-01 00:00:00

    Parameters
    timestamp: a number representing an epoch timestamp

    Return
    A decimal representation of the original timestamp if it is valid
    """

    # Duh...
    try:
        timestamp = Decimal(timestamp)
    except InvalidOperation:
        raise TimestampException('Timestamp must be a number')

    # Also Duh...
    if isinf(timestamp):
        raise TimestampException('Timestamp cannot be infinite')

    # No such epoch timestamps before 0
    if timestamp < 0:
        raise TimestampException('Timestamp cannot be less than zero')

    # Prevent issues with overflows by passing in a massive number
    if timestamp >= MAX_TIMESTAMP:
        raise TimestampException('Timestamp must be before the year 3000')

    return timestamp


def arguments_valid(algorithm, size, analysis):
    """
    Function Name: arguments_valid
    This function checks if the configuration items sent from the front end are valid

    :param algorithm: the type of algorithm being used.
    :param size: the window size for the amount of pcaps to analyze
    :return: True if all checks passes, False if at least one fails
    """

    if check_config(algorithm) and check_size(size) and check_analysis(analysis):
        check = True
    else:
        check = False

    return check


def check_config(algorithm):
    """
    Function Name: check_config
    Checks the algorithm thats been passed through the function,

    :param algorithm:
    :return:
    """
    results = False

    if algorithm == 'Benford':
        results = True
    elif algorithm == 'Zipf':
        results = True

    return results


def check_size(size):
    """
    Function Name: check_size
    Checks the size of the Window for analysis, currently it is checking if it is either 1000 or 2000, (subject to change)

    :param size: a string that is converted to an integer
    :return: True if size is greater than 0, a value error if it is not
    """
    int_size = int(size)

    if int_size > 0:
        results = True
    else:
        logging.error("Cannot have a window size less than or equal to 0")
        raise ValueError("Cannot have a window size less than or equal to 0")
    return results


def check_analysis(analysis):
    """
    Function Name: check_analysis
    Checks the analysis variable that was passed through, it is checking if it is length vs time based.

    :param analysis: a string that identifies a configuration option (time/length)
    :return: response, a boolean type variable.
    """
    if analysis == 'Time':
        response = True
    elif analysis == 'Length':
        response = True
    else:
        response = False

    return response
